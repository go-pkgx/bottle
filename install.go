package bottle

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Exec runs (or, on UNIX, replaces the current process image with) the target
// binary; overridable in tests. Its concrete value is platform-specific:
//   - UNIX (exec_unix.go): syscall.Exec — replaces the process, never returns
//     on success.
//   - Windows (exec_windows.go): spawns the child with inherited stdio, waits,
//     and exits the parent with the child's exit code (Windows has no execve).
//
// The signature is identical on every platform, so callers are unchanged.
var Exec func(argv0 string, argv []string, env []string) error

// ResolveBinPath maps a logical bin path (…/bin/foo) to the file that actually
// exists on disk. On Windows it prefers "foo.exe" (the PE image the toolchain
// produces), falling back to the bare name; on UNIX it is the identity. This
// keeps BinNames/PrimaryBin returning logical, extension-free names while the
// run/stub sites resolve to the real executable.
func ResolveBinPath(bin string) string {
	if goos() == "windows" && !strings.HasSuffix(bin, ".exe") {
		if _, err := os.Stat(bin + ".exe"); err == nil {
			return bin + ".exe"
		}
	}
	return bin
}

// BinNames returns the base names of the binaries a package provides, falling
// back to the project's leaf name when it declares no `provides:`.
func BinNames(project string, provides []string) []string {
	return BinNamesFor(project, provides, "")
}

// BinNamesFor is BinNames with the package's version in hand, so a recipe that
// names its binary AFTER that version is reachable.
//
// apache.org/apr-util provides exactly one program:
//
//	provides:
//	  - bin/apu-{{ version.major }}-config
//
// and taken verbatim that is a file called `apu-{{ version.major }}-config`,
// which exists nowhere. `pkgx apache.org/apr-util` answered
//
//	command not found in the requested packages: apu-{{ version.major }}-config
//
// Six pantry recipes put a moustache in a bin/ name; five of them also list a
// plain one and were saved by it. This is the sixth.
//
// An empty version means "do not expand": the callers that have no version are
// asking what the recipe SAYS, and a placeholder silently becoming empty there
// would turn one unusable name into a different unusable name.
func BinNamesFor(project string, provides []string, version string) []string {
	var names []string
	for _, prov := range provides {
		if prov = strings.TrimSpace(prov); strings.HasPrefix(prov, "bin/") {
			if version != "" {
				prov = expandRecipeVars(prov, "", version)
			}
			names = append(names, filepath.Base(prov))
		}
	}
	if len(names) == 0 {
		names = append(names, filepath.Base(project))
	}
	return names
}

// PrimaryBin picks the binary to run for a project: the one whose name matches
// the project's path leaf (gnu.org/wget -> wget) or its domain's second-level
// label (perl.org -> perl, not the first-listed corelist), else the first
// provided binary.
func PrimaryBin(project string, provides []string) string {
	return PrimaryBinFor(project, provides, "")
}

// PrimaryBinFor is PrimaryBin with the version in hand — see BinNamesFor.
func PrimaryBinFor(project string, provides []string, version string) string {
	names := BinNamesFor(project, provides, version)
	cands := []string{filepath.Base(project)}
	if !strings.Contains(project, "/") {
		if i := strings.Index(project, "."); i > 0 {
			cands = append(cands, project[:i])
		}
	}
	for _, c := range cands {
		for _, n := range names {
			if n == c {
				return n
			}
		}
	}
	return names[0]
}

// IsELF reports whether the file at p starts with the ELF magic.
func IsELF(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// PrefixOf returns the installed prefix directory <dir>/<project>/v<version>
// for the Resolved whose Project equals project in the closure, or "" if the
// project is not part of the closure.
func PrefixOf(project string, closure []Resolved, dir string) string {
	for _, r := range closure {
		if r.Project == project {
			return filepath.Join(dir, project, "v"+r.Version.Raw)
		}
	}
	return ""
}

// InstalledVersions lists the versions of a project present in a store,
// newest first.
//
// The other direction from PrefixOf: that one COMPOSES a path from a
// version somebody already resolved, this one ENUMERATES what is on disk.
// Nothing asked the second question until a browser wanted to mark what you
// already have, and the convention — <dir>/<project>/v<version> — was
// spelled out at nine call sites with no reader anywhere.
//
// Newest first by VERSION order, not by name: a directory listing is
// alphabetical, and alphabetically "v1.9" sorts above "v1.10", so the first
// entry would be the wrong one to put beside a project's name.
//
// The `v1` / `v1.2` / `v*` ALIASES writeVersionLinks leaves beside the real
// directories are symlinks, and os.ReadDir lstats, so their IsDir is false
// and the directory filter drops them. That is load-bearing rather than
// incidental: counted as versions they would make one install look like
// three, and `pkgx ls` would say a project has versions nobody can name.
//
// An unreadable or absent directory is no versions, not an error. "Nothing
// installed" is the normal state of almost every project in a catalogue of
// two thousand, and a browser cannot stop to report it.
func InstalledVersions(project, dir string) []string {
	ents, err := os.ReadDir(filepath.Join(dir, project))
	if err != nil {
		return nil
	}
	var vs []Ver
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "v") {
			continue
		}
		raw := strings.TrimPrefix(e.Name(), "v")
		// A digit after the v is what tells a version directory from a
		// word. It also drops the `v*` alias, whose second character is
		// not one.
		if raw == "" || raw[0] < '0' || raw[0] > '9' {
			continue
		}
		vs = append(vs, ParseVer(raw))
	}
	sort.Slice(vs, func(i, j int) bool { return cmpVer(vs[i], vs[j]) > 0 })
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Raw)
	}
	return out
}

// Stage describes where a closure's bottles LIVE while stubs are written and
// where they will live when the stubs RUN. The two differ whenever a rootfs is
// assembled somewhere other than the machine that will boot it — the whole
// point of staging.
type Stage struct {
	// Dir is where the bottles are on the machine writing the stubs. Files are
	// checked for existence here.
	Dir string
	// GuestDir is the path those same bottles will have where the stubs run —
	// "/pkgx" for an image staged under /tmp/rootfs. Empty means Dir: the
	// staging machine IS the running machine (pkgm's case).
	GuestDir string
	// Prefix is where <prefix>/bin receives the stubs, on the staging machine.
	Prefix string
	// OS and Arch are the pkgx slug of the target. Empty means the host's —
	// they select which platform's `provides:` list names the binaries.
	OS, Arch string
}

// StubBins writes a small env-setting shell stub into <prefix>/bin for every
// binary in the closure, mirroring the reference pkgm: the stub exports the
// closure's LD_LIBRARY_PATH and exec's the real bottle binary.
func StubBins(closure []Resolved, dir, prefix string) (int, error) {
	return StubBinsStaged(closure, Stage{Dir: dir, Prefix: prefix})
}

// StubBinsStaged is StubBins for a rootfs being assembled elsewhere.
//
// A stub is a shell script holding ABSOLUTE paths — the closure's
// LD_LIBRARY_PATH and the bottle binary to exec. Written with the staging
// machine's paths, every one of them is wrong the moment the rootfs boots:
// they point at /tmp/whatever-the-builder-used, a directory the guest does not
// have. So the paths baked in come from GuestDir while the existence checks
// use Dir.
func StubBinsStaged(closure []Resolved, s Stage) (int, error) {
	dir, prefix := s.Dir, s.Prefix
	guestDir := s.GuestDir
	if guestDir == "" {
		guestDir = dir
	}
	osn, arch := s.OS, s.Arch
	if osn == "" || arch == "" {
		osn, arch = HostSlug()
	}
	binDir := filepath.Join(prefix, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return 0, err
	}
	libPath := LibPath(closure, dir)
	if guestDir != dir {
		libPath = strings.ReplaceAll(libPath, dir, guestDir)
	}
	n := 0
	for _, r := range closure {
		pkgPrefix := filepath.Join(dir, r.Project, "v"+r.Version.Raw)
		guestPrefix := filepath.Join(guestDir, r.Project, "v"+r.Version.Raw)
		_, provides, err := FetchMetaFor(r.Project, osn, arch)
		if err != nil {
			continue
		}
		for _, name := range BinNamesFor(r.Project, provides, r.Version.Raw) {
			real := filepath.Join(pkgPrefix, "bin", name)
			if _, err := os.Stat(real); err != nil {
				continue
			}
			stub := fmt.Sprintf("#!/bin/sh\nexport LD_LIBRARY_PATH=\"%s${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"\nexec \"%s\" \"$@\"\n",
				libPath, filepath.Join(guestPrefix, "bin", name))
			dst := filepath.Join(binDir, name)
			_ = os.Remove(dst)
			if err := os.WriteFile(dst, []byte(stub), 0o755); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// LibDirs returns every library directory in an installed closure (including
// glibc's versioned sub-libdir on linux). It is the list form of LibPath, used
// where an OS-native path separator is required (Windows joins with ";" and
// resolves DLLs from these dirs via PATH, so a ":"-joined string is wrong).
func LibDirs(closure []Resolved, dir string) []string {
	var paths []string
	for _, r := range closure {
		prefix := filepath.Join(dir, r.Project, "v"+r.Version.Raw)
		for _, sub := range []string{"lib", "lib64"} {
			p := filepath.Join(prefix, sub)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				paths = append(paths, p)
			}
			matches, _ := filepath.Glob(filepath.Join(prefix, sub, "glibc-*"))
			paths = append(paths, matches...)
		}
	}
	return paths
}

// LibPath returns a ":"-joined library path covering every lib dir in an
// installed closure (including glibc's versioned sub-libdir). It is the value
// of $LD_LIBRARY_PATH used on linux; on Windows use LibDirs with the native
// separator instead.
func LibPath(closure []Resolved, dir string) string {
	return strings.Join(LibDirs(closure, dir), ":")
}

// LoaderName is the dynamic-loader soname for the current architecture.
func LoaderName() string { return LoaderNameFor(goarch()) }

// FindLoader locates the pkgx glibc dynamic loader in an installed closure.
func FindLoader(dir string) string {
	return FindLoaderFor(dir, goarch())
}

// FindLoaderFor is FindLoader for an EXPLICIT architecture: the loader of the
// rootfs being STAGED, whose ELF name (ld-linux-aarch64.so.1 vs
// ld-linux-x86-64.so.2) is the target's, not the staging machine's.
func FindLoaderFor(dir, arch string) string {
	name := LoaderNameFor(arch)
	if name == "" {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(dir, GlibcProject, "v*", "lib", "glibc-*", name))
	if len(matches) > 0 {
		return matches[len(matches)-1]
	}
	return ""
}

var loaderDirs = []string{"/lib", "/lib64"}

// SetupScratchRootfs makes the pkgx loader and a shell available at their
// canonical absolute paths (best-effort). On a FROM-scratch image this lets
// every bottle ELF — the one we exec AND any child processes it spawns —
// resolve its PT_INTERP=/lib/ld-linux natively, and (when shellPath is set)
// lets "#!/bin/sh" wrapper scripts resolve to the pkgx bash we installed. On a
// normal system these paths already exist, so os.Symlink fails and is ignored
// (no clobbering).
func SetupScratchRootfs(loader, shellPath string) {
	if name := LoaderName(); name != "" {
		for _, d := range loaderDirs {
			_ = os.MkdirAll(d, 0o755)
			_ = os.Symlink(loader, filepath.Join(d, name))
		}
	}
	if shellPath != "" {
		_ = os.MkdirAll("/bin", 0o755)
		_ = os.Symlink(shellPath, "/bin/sh")
	}
}

// MergeClosures appends the packages of b not already in a (dedup by project).
func MergeClosures(a, b []Resolved) []Resolved {
	have := map[string]bool{}
	for _, r := range a {
		have[r.Project] = true
	}
	for _, r := range b {
		if !have[r.Project] {
			a = append(a, r)
			have[r.Project] = true
		}
	}
	return a
}

// FindClosureBin returns the path to <project>/…/bin/<name> if that project is
// in the installed closure, else "".
func FindClosureBin(closure []Resolved, dir, project, name string) string {
	for _, r := range closure {
		if r.Project == project {
			p := filepath.Join(dir, project, "v"+r.Version.Raw, "bin", name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// CanonicalLoaderExists reports whether /lib{,64}/ld-linux-* is present.
func CanonicalLoaderExists() bool {
	name := LoaderName()
	if name == "" {
		return false
	}
	for _, d := range loaderDirs {
		if _, err := os.Lstat(filepath.Join(d, name)); err == nil {
			return true
		}
	}
	return false
}

// SetupScratchRootfsAt is SetupScratchRootfs against an arbitrary root, for a
// rootfs being STAGED rather than the one being run on. A builder assembling a
// FROM-scratch image on a host cannot write /lib and /bin — those belong to the
// host — so it hands the staging directory here instead.
//
// loaderName is the loader's ELF name for the TARGET architecture, which is not
// necessarily the host's: LoaderName() answers for the host, LoaderNameFor()
// for whatever is being built.
func SetupScratchRootfsAt(root, loaderName, loaderTarget, shellTarget string) error {
	if loaderName != "" && loaderTarget != "" {
		for _, d := range loaderDirs {
			dir := filepath.Join(root, d)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			if err := os.Symlink(loaderTarget, filepath.Join(dir, loaderName)); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	if shellTarget != "" {
		dir := filepath.Join(root, "bin")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		// BOTH names, and the second is not a convenience.
		//
		// /bin/sh is posed because make runs every recipe line through it.
		// /bin/bash is posed because the WORLD'S scripts say `#!/bin/bash`,
		// and a shebang that cannot be resolved fails as if the script
		// itself were missing:
		//
		//	FAIL gnu.org/readline 8.3: fork/exec
		//	  /pkgx/gnu.org/glibc/v2.44/bin/ldd: no such file or directory
		//
		// readline's test runs `ldd`, glibc ships bin/ldd as a generated
		// BASH script, and the second sovereign generation's rootfs had no
		// /bin/bash. ENOENT from exec names the script, never the
		// interpreter, which is why this took a reading of the staging code
		// rather than of the log.
		//
		// Both point at the same bash. Posing a shell at a canonical
		// absolute path is a thing this rootfs already does and already
		// argues for; `sh` alone was the arbitrary half.
		for _, name := range []string{"sh", "bash"} {
			if err := os.Symlink(shellTarget, filepath.Join(dir, name)); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	return nil
}

// LoaderNameFor answers LoaderName for an explicit architecture, so a builder
// can name the loader of the image it is assembling.
//
// An architecture that is not here returns "", and the caller must say so
// rather than report a missing glibc: the two look identical from the outside
// and are nothing alike. `bk builder` on linux/s390x said
//
//	builder: no s390x loader in the staged glibc — is gnu.org/glibc in the
//	toolchain?
//
// with gnu.org/glibc plainly in the toolchain and all 42 packages installed.
//
// s390x's loader is NOT named after its architecture, and that is the one
// thing about this table that cannot be guessed. The two entries above both
// read `ld-linux-<arch>.so.N`; extending that pattern gives
// `ld-linux-s390x.so.1`, which does not exist. The real name comes from OUR
// OWN artefacts, twice over and independently:
//
//   - 362 occurrences of `ld64.so.1 is NEEDED` across the s390x lane's logs,
//     and not one `ld-linux-*.so` (recorded in go-pkgx/packages'
//     overrides/gnu.org-glibc.hcl, which needed the same fact for $LDSO);
//   - `readelf -l` on the published s390x libc.so.6 (go-pkgx/bk#263):
//     `/…/gnu.org/glibc/v2.44+brewing/lib/glibc-2.44/ld64.so.1`.
//
// ppc64le, riscv64 and loong64 are deliberately ABSENT. bk is TESTED on them
// and no bottle is BUILT for them, so there is no artefact here to read a name
// out of — and a name deduced from a pattern is exactly what this comment
// exists to warn against. Add one when a bottle for that architecture can be
// read.
func LoaderNameFor(arch string) string {
	return map[string]string{
		"aarch64": "ld-linux-aarch64.so.1",
		"x86-64":  "ld-linux-x86-64.so.2",
		"s390x":   "ld64.so.1",
	}[arch]
}
