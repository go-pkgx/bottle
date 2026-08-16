package bottle

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The "implicit system" shared libraries: bottles link them but never declare
// them as pkgx dependencies, because pkgx historically assumes the host libc /
// toolchain runtime. On a `FROM scratch` image there is no host, so the
// installer must supply them from pkgx bottles too. Each group maps to the
// bottle that provides it.
var (
	glibcSonames = []string{
		"libc.so", "libm.so", "libpthread.so", "libdl.so", "librt.so",
		"libresolv.so", "libutil.so", "libnsl.so", "libanl.so", "ld-linux",
	}
	libstdcxxSonames = []string{"libgcc_s.so", "libstdc++.so"}
	gccSonames       = []string{"libatomic.so", "libgomp.so", "libquadmath.so", "libitm.so"}
)

// sonameProject maps a shared-library soname stem to the pkgx project that
// provides it, for the common libraries that packages link but frequently do
// NOT declare in their package.yml dependencies (compression, text, tls…).
// package.yml runtime graphs are incomplete; on FROM scratch the closure must
// be complete, so we resolve the gap from the bottles' own DT_NEEDED.
var sonameProject = map[string]string{
	"libz":         "zlib.net",
	"libbz2":       "sourceware.org/bzip2",
	"liblzma":      "tukaani.org/xz",
	"libzstd":      "facebook.com/zstd",
	"liblz4":       "lz4.org",
	"libssl":       "openssl.org",
	"libcrypto":    "openssl.org",
	"libcurl":      "curl.se",
	"libncurses":   "invisible-island.net/ncurses",
	"libncursesw":  "invisible-island.net/ncurses",
	"libtinfo":     "invisible-island.net/ncurses",
	"libreadline":  "gnu.org/readline",
	"libffi":       "sourceware.org/libffi",
	"libpcre2-8":   "pcre.org/v2",
	"libintl":      "gnu.org/gettext",
	"libiconv":     "gnu.org/libiconv",
	"libidn2":      "gnu.org/libidn2",
	"libunistring": "gnu.org/libunistring",
	"libpsl":       "rockdaboot.github.io/libpsl",
	"libnghttp2":   "nghttp2.org",
	"libexpat":     "libexpat.github.io",
	"libxml2":      "gnome.org/libxml2",
	"libsqlite3":   "sqlite.org",
	"libgmp":       "gnu.org/gmp",
	"libmpfr":      "gnu.org/mpfr",
	"libcrypt":     "github.com/besser82/libxcrypt", // glibc 2.38+ dropped libcrypt
	"libtinfow":    "invisible-island.net/ncurses",  // wide-char ncurses terminfo
	"libFLAC":      "xiph.org/flac",
	"libtheora":    "theora.org",
	"libgit2":      "libgit2.org",
	"libcbor":      "github.com/PJK/libcbor",
	"libavro":      "apache.org/avro",
	"libprotoc":    "protobuf.dev", // protoc lib; libprotobuf is prefix-mapped below
	"libclang":     "llvm.org",
	"libgflags":    "gflags.github.io",
	"libcap":       "kernel.org/libcap",
	// eudev is the lightweight standalone libudev provider (a few files) vs
	// pulling all of systemd (200+ binaries) just for libudev.so.1.
	"libudev": "github.com/eudev-project/eudev",
}

// sonamePrefixProject maps a soname PREFIX to its provider, for libraries that
// ship many differently-named sonames from one project (e.g. abseil's dozens
// of libabsl_*.so). Consulted when the exact-stem map misses.
var sonamePrefixProject = map[string]string{
	"libabsl":     "abseil.io",
	"libprotobuf": "protobuf.dev",
	"libre2":      "github.com/google/re2",
	"libboost":    "boost.org", // libboost_regex/system/… all ship from boost.org
}

// projectForSoname resolves a NEEDED soname to its providing pkgx project via
// the exact-stem map first, then the prefix map. Returns "" if unknown.
func projectForSoname(soname string) string {
	if p := sonameProject[sonameBase(soname)]; p != "" {
		return p
	}
	for pfx, p := range sonamePrefixProject {
		if strings.HasPrefix(soname, pfx) {
			return p
		}
	}
	return ""
}

// sonameBase reduces a soname like "libz.so.1" to its stem "libz".
func sonameBase(soname string) string {
	if i := strings.Index(soname, ".so"); i >= 0 {
		return soname[:i]
	}
	return soname
}

// scanNeeded walks every ELF under the given installed prefixes and returns the
// set of DT_NEEDED sonames across all of them (pure Go, via debug/elf).
func scanNeeded(prefixes []string) map[string]bool {
	needed := map[string]bool{}
	for _, prefix := range prefixes {
		_ = filepath.Walk(prefix, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || !info.Mode().IsRegular() {
				return nil
			}
			f, err := elf.Open(p)
			if err != nil {
				return nil // not an ELF
			}
			defer f.Close()
			libs, err := f.ImportedLibraries()
			if err != nil {
				return nil
			}
			for _, l := range libs {
				needed[l] = true
			}
			return nil
		})
	}
	return needed
}

// implicitRoots inspects a set of NEEDED sonames and returns the extra pkgx
// bottles required to satisfy the implicit system libraries on a scratch image.
// glibc is always included on linux (every dynamic ELF needs the loader+libc).
func implicitRoots(needed map[string]bool) map[string]string {
	// glibc is the one implicit root whose newest is not always the right one:
	// its loader refuses to run below the kernel floor it was built against, so
	// the constraint is kernel-aware (and PKGX_GLIBC-pinnable). See glibc.go.
	roots := map[string]string{GlibcProject: GlibcConstraint()}
	if matchesAny(needed, libstdcxxSonames) {
		roots["gnu.org/gcc/libstdcxx"] = "*"
	}
	if matchesAny(needed, gccSonames) {
		roots["gnu.org/gcc"] = "*"
	}
	return roots
}

// isImplicitSoname reports whether a soname belongs to one of the implicit
// system groups — glibc, the libstdc++/libgcc pair, the gcc runtime libs. Those
// are the implicit block's business, and it installs them from their project
// groups rather than from the soname map. The soname loop must not treat one as
// unprovided: `provided` is sampled at the top of a round, BEFORE the implicit
// install of that same round, so libstdc++.so.6 still looks missing there.
func isImplicitSoname(soname string) bool {
	one := map[string]bool{soname: true}
	return matchesAny(one, glibcSonames) || matchesAny(one, libstdcxxSonames) || matchesAny(one, gccSonames)
}

// matchesAny reports whether any needed soname starts with one of the prefixes.
func matchesAny(needed map[string]bool, prefixes []string) bool {
	for soname := range needed {
		for _, p := range prefixes {
			if strings.HasPrefix(soname, p) {
				return true
			}
		}
	}
	return false
}

// prefixesOf returns the installed prefix directories of a closure.
func prefixesOf(closure []Resolved, dir string) []string {
	var out []string
	for _, r := range closure {
		out = append(out, filepath.Join(dir, r.Project, "v"+r.Version.Raw))
	}
	return out
}

// availableSonames returns the set of shared-library sonames present in the
// installed closure's lib dirs (what the closure already provides).
func availableSonames(prefixes []string) map[string]bool {
	have := map[string]bool{}
	for _, prefix := range prefixes {
		for _, sub := range []string{"lib", "lib64"} {
			matches, _ := filepath.Glob(filepath.Join(prefix, sub, "*.so*"))
			deep, _ := filepath.Glob(filepath.Join(prefix, sub, "*", "*.so*"))
			for _, m := range append(matches, deep...) {
				have[filepath.Base(m)] = true
			}
		}
	}
	return have
}

// CompleteClosure resolves a package's declared closure, installs it, then
// iteratively reads the bottles' ELF DT_NEEDED and pulls whatever bottle
// provides each unsatisfied soname — the implicit glibc/gcc system libraries
// and the common undeclared libraries (libz, libbz2, ncurses…) that
// package.yml graphs omit — until every NEEDED soname is satisfied. This makes
// the closure complete enough to run on a `FROM scratch` image.
func CompleteClosure(roots map[string]string, dir string) ([]Resolved, error) {
	closure, err := ResolveClosure(roots)
	if err != nil {
		return nil, err
	}
	for _, r := range closure {
		if _, err := Install(r, dir); err != nil {
			return nil, err
		}
	}
	if goos() != "linux" {
		return closure, nil
	}
	have := map[string]bool{}
	installedVer := map[string]bool{} // "project@version" already in the closure
	for _, r := range closure {
		have[r.Project] = true
		installedVer[r.Project+"@"+r.Version.Raw] = true
	}
	triedSoname := map[string]bool{} // sonames we've already attempted to provide
	// Fixpoint: keep pulling providers of unsatisfied sonames until none remain.
	for round := 0; round < 8; round++ {
		prefixes := prefixesOf(closure, dir)
		needed := scanNeeded(prefixes)
		provided := availableSonames(prefixes)
		changed := false

		// Implicit system libraries (glibc always; gcc runtime when linked).
		// These have one obvious latest version, so resolve them as "*".
		implicit := map[string]string{}
		for p, c := range implicitRoots(needed) {
			if !have[p] {
				implicit[p] = c
			}
		}
		if len(implicit) > 0 {
			more, err := ResolveClosure(implicit)
			if err != nil {
				return nil, err
			}
			for _, r := range more {
				if have[r.Project] {
					continue
				}
				if _, err := Install(r, dir); err != nil {
					return nil, err
				}
				have[r.Project] = true
				closure = append(closure, r)
				changed = true
			}
		}

		// Undeclared regular-package libraries, mapped by soname. Pull the
		// NEWEST version of the provider that actually ships the exact soname —
		// NOT just the latest release, because a soname carries an ABI version
		// and a newer release may have bumped it (e.g. libxml2 2.15 ships
		// libxml2.so.16, but a binary linked against libxml2.so.2 needs a 2.x
		// bottle; likewise openssl 3 ships libssl.so.3, not libssl.so.1.1).
		for soname := range needed {
			if provided[soname] || triedSoname[soname] || isImplicitSoname(soname) {
				continue
			}
			// NB: do NOT skip when have[proj] — the provider may already be in
			// the closure at a version that ships a DIFFERENT abi soname (e.g.
			// libxml2 2.15 pulled as a declared dep ships libxml2.so.16, yet a
			// binary needs libxml2.so.2). Pull the exact-soname version too;
			// both lib dirs sit on LD_LIBRARY_PATH and each soname resolves.
			triedSoname[soname] = true // once per soname, so a warning is said once
			r, ok := provideSoname(soname, dir)
			if !ok {
				continue
			}
			proj := r.Project
			key := r.Project + "@" + r.Version.Raw
			if installedVer[key] {
				continue
			}
			installedVer[key] = true
			have[proj] = true
			closure = append(closure, r)
			changed = true
		}

		if !changed {
			break
		}
	}
	return closure, nil
}

// provideSoname installs the bottle that provides soname, or says why it could
// not. ok=false means the closure stays INCOMPLETE — and an incomplete closure
// does not fail here: it fails later, when the binary starts and reports
// "<soname>: cannot open shared object file" with nothing pointing back at the
// resolution that gave up. Each of the three ways to give up is distinct, and
// distinguishing them is the whole point: an unmapped soname needs an entry in
// sonameProject, a lookup error usually means the registry in use does not
// carry the provider at all (perl's libcrypt.so.1 was simply absent from a
// local cache, and the silence cost an hour), and "no version provides it"
// means the provider moved past that ABI.
func provideSoname(soname, dir string) (Resolved, bool) {
	proj := projectForSoname(soname)
	if proj == "" {
		warn("%s is NEEDED but no pkgx project is mapped to that soname", soname)
		return Resolved{}, false
	}
	r, ok, err := installProvidingSoname(proj, soname, dir)
	switch {
	case err != nil:
		warn("cannot provide %s from %s: %v", soname, proj, err)
		return Resolved{}, false
	case !ok:
		warn("no published %s version provides %s", proj, soname)
		return Resolved{}, false
	}
	return r, true
}

// installProvidingSoname installs the newest available version of project whose
// bottle actually provides the exact soname, trying newest→oldest, and returns
// that matching bottle. ok is false if no examined version ships the soname.
// Sonames carry an ABI version a project's latest release may have moved past,
// so "latest" is not always the right bottle for a specific soname.
func installProvidingSoname(project, soname, dir string) (Resolved, bool, error) {
	vs, err := FetchVersions(project)
	if err != nil {
		return Resolved{}, false, err
	}
	const maxTry = 40 // bound the walk for a soname no examined version provides
	tried := 0
	for _, v := range candidateOrder(vs, soname) {
		if tried >= maxTry {
			break
		}
		tried++
		r := Resolved{project, v}
		if _, err := Install(r, dir); err != nil {
			continue // no bottle for this version/platform — try the next one
		}
		prefix := filepath.Join(dir, r.Project, "v"+r.Version.Raw)
		if availableSonames([]string{prefix})[soname] {
			return r, true, nil
		}
	}
	return Resolved{}, false, nil
}

// candidateOrder returns versions newest-first, but floats versions whose
// leading number equals the soname's ABI tail to the front — so a version that
// drifted its soname (e.g. libssl.so.1.1 is openssl 1.1.x, not the latest 3.x;
// libprotoc.so.25.x is protobuf 25.x) is found without walking every release.
func candidateOrder(vs []Ver, soname string) []Ver {
	hint := sonameABI(soname)
	var match, rest []Ver
	for i := len(vs) - 1; i >= 0; i-- { // newest first
		v := vs[i]
		if hint != "" && len(v.Nums) > 0 && strconv.Itoa(v.Nums[0]) == hint {
			match = append(match, v)
		} else {
			rest = append(rest, v)
		}
	}
	return append(match, rest...)
}

// sonameABI extracts the first numeric component after ".so." in a soname,
// e.g. "libssl.so.1.1" -> "1", "libprotoc.so.25.7.0" -> "25", "libz.so" -> "".
func sonameABI(soname string) string {
	i := strings.Index(soname, ".so.")
	if i < 0 {
		return ""
	}
	tail := soname[i+len(".so."):]
	j := 0
	for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
		j++
	}
	return tail[:j]
}
