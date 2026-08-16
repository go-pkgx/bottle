package bottle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatchesAny(t *testing.T) {
	needed := map[string]bool{"libc.so.6": true, "libgcc_s.so.1": true}
	if !matchesAny(needed, libstdcxxSonames) {
		t.Error("libgcc_s should match libstdcxx group")
	}
	if matchesAny(needed, gccSonames) {
		t.Error("no libatomic present")
	}
	if !matchesAny(needed, glibcSonames) {
		t.Error("libc should match glibc group")
	}
}

func TestImplicitRoots(t *testing.T) {
	// bare glibc only
	r := implicitRoots(map[string]bool{"libc.so.6": true})
	if _, ok := r["gnu.org/glibc"]; !ok {
		t.Error("glibc always included")
	}
	if _, ok := r["gnu.org/gcc/libstdcxx"]; ok {
		t.Error("no libstdcxx for pure C")
	}
	// C++ needs libstdcxx
	r = implicitRoots(map[string]bool{"libstdc++.so.6": true, "libgcc_s.so.1": true})
	if _, ok := r["gnu.org/gcc/libstdcxx"]; !ok {
		t.Error("libstdcxx expected for C++")
	}
	// libatomic pulls gnu.org/gcc
	r = implicitRoots(map[string]bool{"libatomic.so.1": true})
	if _, ok := r["gnu.org/gcc"]; !ok {
		t.Error("gcc expected for libatomic")
	}
}

func TestProjectForSoname(t *testing.T) {
	// exact-stem map
	if projectForSoname("libz.so.1") != "zlib.net" {
		t.Error("libz exact stem")
	}
	// prefix map (abseil ships many differently-named libabsl_*.so)
	if projectForSoname("libabsl_die_if_null.so.2505.0.0") != "abseil.io" {
		t.Error("libabsl prefix")
	}
	if projectForSoname("libprotobuf-lite.so.32") != "protobuf.dev" {
		t.Error("libprotobuf prefix")
	}
	// unknown
	if projectForSoname("libwhatever.so.9") != "" {
		t.Error("unknown should be empty")
	}
}

func TestPrefixesOf(t *testing.T) {
	closure := []Resolved{{"acme.org/tool", ParseVer("1.2.3")}}
	got := prefixesOf(closure, "/pkgx")
	if len(got) != 1 || got[0] != filepath.Join("/pkgx", "acme.org/tool", "v1.2.3") {
		t.Errorf("prefixesOf = %v", got)
	}
}

func TestSonameBase(t *testing.T) {
	cases := map[string]string{
		"libz.so.1":     "libz",
		"libpcre2-8.so": "libpcre2-8",
		"libc.so.6":     "libc",
		"weird":         "weird",
	}
	for in, want := range cases {
		if got := sonameBase(in); got != want {
			t.Errorf("sonameBase(%q)=%q want %q", in, got, want)
		}
	}
	if sonameProject["libz"] != "zlib.net" {
		t.Error("libz should map to zlib.net")
	}
}

func TestAvailableSonames(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "p", "v1")
	_ = os.MkdirAll(filepath.Join(prefix, "lib", "glibc-2.44"), 0o755)
	_ = os.WriteFile(filepath.Join(prefix, "lib", "libfoo.so.1"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(prefix, "lib", "glibc-2.44", "libc.so.6"), []byte("x"), 0o644)
	got := availableSonames([]string{prefix})
	if !got["libfoo.so.1"] || !got["libc.so.6"] {
		t.Errorf("availableSonames = %v", got)
	}
}

func TestScanNeededNonELF(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "not-an-elf"), []byte("hello"), 0o644)
	if n := scanNeeded([]string{dir}); len(n) != 0 {
		t.Errorf("expected empty for non-ELF, got %v", n)
	}
}

func TestSonameABI(t *testing.T) {
	cases := map[string]string{
		"libssl.so.1.1":       "1",
		"libprotoc.so.25.7.0": "25",
		"libfoo.so.2":         "2",
		"libz.so":             "", // ".so" but no ".so.<n>"
		"weird":               "",
	}
	for in, want := range cases {
		if got := sonameABI(in); got != want {
			t.Errorf("sonameABI(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCandidateOrder(t *testing.T) {
	vs := []Ver{ParseVer("1.1.1w"), ParseVer("3.0.0"), ParseVer("3.5.0")} // ascending
	// libssl.so.1.1 -> hint "1" floats openssl 1.x ahead of the newer 3.x.
	got := candidateOrder(vs, "libssl.so.1.1")
	if got[0].Raw != "1.1.1w" {
		t.Errorf("hint match should lead, got %q", got[0].Raw)
	}
	if got[1].Raw != "3.5.0" || got[2].Raw != "3.0.0" {
		t.Errorf("rest should be newest-first, got %v", []string{got[1].Raw, got[2].Raw})
	}
	// no ABI hint -> pure newest-first.
	if got = candidateOrder(vs, "libz.so"); got[0].Raw != "3.5.0" {
		t.Errorf("no-hint newest-first, got %q", got[0].Raw)
	}
}

func TestInstallProvidingSoname(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"xml.org/libxml2": {
			versions: []string{"2.13.9", "2.15.3"},
			yaml:     "provides:\n  - bin/xml\n",
			// the newer release bumped the soname; the older one still ships .so.2
			filesByVer: map[string]map[string]string{
				"2.15.3": {"lib/libxml2.so.16": "x"},
				"2.13.9": {"lib/libxml2.so.2": "x"},
			},
		},
	})()
	dir := t.TempDir()
	// The walk must skip 2.15.3 (ships .so.16) and fall back to 2.13.9 (.so.2).
	r, ok, err := installProvidingSoname("xml.org/libxml2", "libxml2.so.2", dir)
	if err != nil || !ok {
		t.Fatalf("expected libxml2.so.2 provider, ok=%v err=%v", ok, err)
	}
	if r.Version.Raw != "2.13.9" {
		t.Errorf("picked v%s, want 2.13.9", r.Version.Raw)
	}
	// a soname no version provides -> ok=false, no error.
	if _, ok, err := installProvidingSoname("xml.org/libxml2", "libnope.so.9", dir); ok || err != nil {
		t.Errorf("absent soname: ok=%v err=%v, want false/nil", ok, err)
	}
	// unknown project -> fetchVersions error surfaces.
	if _, _, err := installProvidingSoname("no.org/x", "libx.so.1", dir); err == nil {
		t.Error("expected error for unknown project")
	}
}

func TestProjectForSonameAddedMappings(t *testing.T) {
	cases := map[string]string{
		"libFLAC.so.12":            "xiph.org/flac",
		"libtheora.so.0":           "theora.org",
		"libgit2.so.1.7":           "libgit2.org",
		"libboost_regex.so.1.82.0": "boost.org", // prefix map
		"libgflags.so.2.2":         "gflags.github.io",
		"libtinfow.so.6":           "invisible-island.net/ncurses",
		"libprotoc.so.25.7.0":      "protobuf.dev",
		"libcap.so.2":              "kernel.org/libcap",
		"libudev.so.1":             "github.com/eudev-project/eudev",
	}
	for in, want := range cases {
		if got := projectForSoname(in); got != want {
			t.Errorf("projectForSoname(%q)=%q want %q", in, got, want)
		}
	}
}

// TestProvideSonameWarns pins each of the three ways the resolver gives up on a
// soname. None of them fails the install, so the ONLY thing standing between
// them and a runtime "cannot open shared object file" hours later is this
// warning — perl's libcrypt.so.1 went missing exactly this way.
func TestProvideSonameWarns(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		// zlib.net is published, but no version ships libz.so.1 in this fixture.
		"zlib.net": {versions: []string{"1.3.2"}, yaml: "provides:\n  - bin/z\n", files: map[string]string{"bin/z": "x"}},
	})()
	var said []string
	Warn = func(msg string) { said = append(said, msg) }
	defer func() { Warn = nil }()

	// 1. no project is mapped to the soname at all
	if _, ok := provideSoname("libwhatever.so.9", t.TempDir()); ok {
		t.Error("unmapped soname must not resolve")
	}
	// 2. the provider is mapped but the registry in use does not carry it
	if _, ok := provideSoname("libcrypt.so.1", t.TempDir()); ok {
		t.Error("absent provider must not resolve")
	}
	// 3. the provider is carried but no version ships that soname
	if _, ok := provideSoname("libz.so.1", t.TempDir()); ok {
		t.Error("soname absent from every version must not resolve")
	}
	for i, want := range []string{
		"libwhatever.so.9 is NEEDED but no pkgx project is mapped to that soname",
		"cannot provide libcrypt.so.1 from github.com/besser82/libxcrypt",
		"no published zlib.net version provides libz.so.1",
	} {
		if i >= len(said) || !strings.Contains(said[i], want) {
			t.Fatalf("warning %d = %q, want it to contain %q (all: %v)", i, said, want, said)
		}
	}
	// A nil Warn is the library default and must stay silent, not panic.
	Warn = nil
	if _, ok := provideSoname("libwhatever.so.9", t.TempDir()); ok {
		t.Error("unmapped soname must not resolve without a Warn either")
	}
}

func TestCompleteClosure(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/tool\n", files: map[string]string{"bin/tool": "x"}},
		"gnu.org/glibc": {versions: []string{"2.44.0"}, yaml: "provides:\n  - bin/ldd\n", files: map[string]string{"lib/glibc-2.44/libc.so.6": "x"}},
	})()
	dir := t.TempDir()
	closure, err := CompleteClosure(map[string]string{"acme.org/tool": "*"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// The fake bottles contain no real ELFs, so scanNeeded finds nothing; on
	// linux glibc is still added unconditionally, on darwin nothing is.
	if GOOS() == "linux" {
		if len(closure) != 2 {
			t.Errorf("linux closure = %d, want 2 (tool+glibc)", len(closure))
		}
	} else if len(closure) != 1 {
		t.Errorf("darwin closure = %d, want 1", len(closure))
	}
}

// TestIsImplicitSoname pins the boundary between the two providers. The soname
// loop samples `provided` at the top of a round, BEFORE the implicit block of
// that same round installs glibc/libstdcxx — so without this test libstdc++.so.6
// looks unprovided and the closure warns about a library it is installing.
func TestIsImplicitSoname(t *testing.T) {
	for _, s := range []string{"libc.so.6", "libm.so.6", "ld-linux-aarch64.so.1", "libstdc++.so.6", "libgcc_s.so.1", "libatomic.so.1"} {
		if !isImplicitSoname(s) {
			t.Errorf("%s belongs to an implicit group", s)
		}
	}
	for _, s := range []string{"libz.so.1", "libcrypt.so.1", "libJIS.so"} {
		if isImplicitSoname(s) {
			t.Errorf("%s is NOT implicit — it must go through the soname map", s)
		}
	}
}
