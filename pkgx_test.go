package bottle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

// --- version parsing / comparison / constraints -----------------------------

func TestParseVerAndCmp(t *testing.T) {
	if got := ParseVer("v1.2.3").Nums; fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("ParseVer nums = %v", got)
	}
	// non-numeric tail (openssl 1.1.1w) truncates at the letter → 1.1.1.
	if got := ParseVer("1.1.1w").Nums; fmt.Sprint(got) != "[1 1 1]" {
		t.Fatalf("ParseVer 1.1.1w = %v", got)
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.0", "1.2", 0},
		{"1.3", "1.2.9", 1},
		{"1.2", "1.10", -1},
	}
	for _, c := range cases {
		if got := cmpVer(ParseVer(c.a), ParseVer(c.b)); got != c.want {
			t.Errorf("cmp(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "*", true},
		{"1.2.3", "", true},
		{"1.2.3", "^1.2", true},
		{"2.0.0", "^1.2", false},
		{"1.2.3", "~1.2", true},
		{"1.3.0", "~1.2", false},
		{"2.6.4", "~2", true},  // major-only tilde matches any 2.x
		{"3.0.0", "~2", false}, // but not 3.x
		{"2.0.9", "~2", true},
		{"1.2.3", ">=1.2.0", true},
		{"1.1.0", ">=1.2.0", false},
		{"1.2.3", "=1.2.3", true},
		{"1.2.4", "=1.2.3", false},
		{"1.2.3", "'^1'", true}, // quoted
		{"0.9.0", "^1", false},
		// upper-bound operators (build-dep pins like `llvm.org: <19`)
		{"18.1.8", "<19", true},
		{"19.0.0", "<19", false},
		{"20.1.0", "<19", false},
		{"16.0.6", "<19", true},
		{"19.0.0", "<=19", true},
		{"19.0.1", "<=19", false},
		{"18.0.0", "<= 19", true}, // spaced upper bound
		{"20.0.0", ">19", true},
		{"19.0.0", ">19", false},
		{"18.9.9", ">19", false},
		{"19.5.0", "> 19", true}, // spaced lower bound
	}
	for _, c := range cases {
		if got := ParseVer(c.v).satisfies(c.c); got != c.want {
			t.Errorf("%s satisfies %q = %v want %v", c.v, c.c, got, c.want)
		}
	}
}

func TestSatisfiesSpacedGE(t *testing.T) {
	if !ParseVer("1.5.0").satisfies(">= 1.2.0") {
		t.Error("spaced >= should parse")
	}
}

// --- host slug --------------------------------------------------------------

func TestHostSlug(t *testing.T) {
	osn, arch := HostSlug()
	if osn != "linux" && osn != "darwin" {
		t.Errorf("os slug = %q", osn)
	}
	if arch == "" {
		t.Error("empty arch slug")
	}
	if GOOS() != osn || GOARCH() != arch {
		t.Errorf("GOOS/GOARCH wrappers disagree with HostSlug")
	}
}

// --- fakePkgx: an in-memory dist.pkgx.dev + pantry --------------------------

type fakePkg struct {
	versions   []string
	yaml       string
	files      map[string]string            // path within prefix -> contents (regular files)
	filesByVer map[string]map[string]string // per-version override of files (for soname-drift tests)
	xzOnly     bool
	noBottle   map[string]bool // versions listed in versions.txt but with no bottle (404)
}

func fakeServer(t *testing.T, pkgs map[string]fakePkg) func() {
	t.Helper()
	osn, arch := HostSlug()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		// pantry: <project>/package.yml
		if strings.HasSuffix(p, "/package.yml") {
			proj := strings.TrimSuffix(p, "/package.yml")
			if pk, ok := pkgs[proj]; ok {
				fmt.Fprint(w, pk.yaml)
				return
			}
			http.NotFound(w, r)
			return
		}
		// versions.txt
		if strings.HasSuffix(p, "/versions.txt") {
			proj := strings.TrimSuffix(p, "/"+osn+"/"+arch+"/versions.txt")
			if pk, ok := pkgs[proj]; ok {
				fmt.Fprint(w, strings.Join(pk.versions, "\n"))
				return
			}
			http.NotFound(w, r)
			return
		}
		// bottle: <project>/<os>/<arch>/v<ver>.tar.(gz|xz)
		for proj, pk := range pkgs {
			pfx := proj + "/" + osn + "/" + arch + "/v"
			if !strings.HasPrefix(p, pfx) {
				continue
			}
			rest := strings.TrimPrefix(p, pfx)
			if pk.xzOnly && strings.HasSuffix(rest, ".tar.gz") {
				http.NotFound(w, r) // force xz fallback
				return
			}
			// A version present in versions.txt but with no published bottle 404s
			// for both extensions (exercises the install-failure/continue paths).
			if v := strings.TrimSuffix(strings.TrimSuffix(rest, ".tar.gz"), ".tar.xz"); pk.noBottle[v] {
				http.NotFound(w, r)
				return
			}
			if strings.HasSuffix(rest, ".tar.gz") {
				ver := strings.TrimSuffix(rest, ".tar.gz")
				files := pk.files
				if pk.filesByVer != nil {
					if f, ok := pk.filesByVer[ver]; ok {
						files = f
					}
				}
				w.Write(makeBottleGz(t, proj, ver, files))
				return
			}
		}
		http.NotFound(w, r)
	})
	// The fixture is a static-HTTP dist serving UNSIGNED bottles, so the
	// fail-closed check refuses every install through it — correctly, now that
	// the install path enforces it too. Tests that exercise verification itself
	// set PKGX_VERIFY back on explicitly.
	t.Setenv("PKGX_VERIFY", "0")
	DistBase, PantryBase = srv.URL, srv.URL
	return srv.Close
}

// makeBottleGz builds a gzip'd tar with the pkgx <project>/v<ver>/... layout.
func makeBottleGz(t *testing.T, project, ver string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	prefix := project + "/v" + ver + "/"
	// a directory entry + a symlink + the regular files
	_ = tw.WriteHeader(&tar.Header{Name: prefix, Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: prefix + "lnk", Typeflag: tar.TypeSymlink, Linkname: "bin"})
	for rel, content := range files {
		_ = tw.WriteHeader(&tar.Header{Name: prefix + rel, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))})
		_, _ = tw.Write([]byte(content))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestFetchVersionsAndPick(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {versions: []string{"1.0.0", "1.2.0", "2.0.0"}, yaml: "provides:\n  - bin/tool\n"},
	})()
	vs, err := FetchVersions("acme.org/tool")
	if err != nil || len(vs) != 3 {
		t.Fatalf("versions err=%v n=%d", err, len(vs))
	}
	v, err := PickVersion("acme.org/tool", "^1.0")
	if err != nil || v.Raw != "1.2.0" {
		t.Fatalf("pick ^1.0 = %v (%v)", v.Raw, err)
	}
	if _, err := PickVersion("acme.org/tool", "^9"); err == nil {
		t.Fatal("expected no-match error for ^9")
	}
}

// upstreamVersionsServer spins a fake upstream pkgx dist that serves a project's
// per-arch versions.txt, and records how many times it was hit. It is used to
// prove the OCI-registry version listing falls back to the upstream dist for
// build-time deps not published to the OCI DistBase.
func upstreamVersionsServer(t *testing.T, project, osn, arch string, versions []string) (url string, hits *int) {
	t.Helper()
	var n int
	want := "/" + project + "/" + osn + "/" + arch + "/versions.txt"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, strings.Join(versions, "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &n
}

// TestVersionsForOCIEmptyFallsBackToUpstream: when the OCI registry lists zero
// versions for a project (a build-dep not published there), VersionsFor falls
// back to the upstream pkgx dist so the concrete install version resolves.
func TestVersionsForOCIEmptyFallsBackToUpstream(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	// The repo exists but carries no tags → ListTags returns an empty slice, no
	// error (the exact shape a not-yet-mirrored build-dep produces on ghcr).
	fr.mu.Lock()
	fr.tags["go-pkgx/packages/llvm.org"] = map[string]bool{}
	fr.mu.Unlock()

	up, hits := upstreamVersionsServer(t, "llvm.org", "linux", "aarch64",
		[]string{"16.0.6", "18.1.8", "20.1.0"})
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-pkgx/packages"), up
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()

	vs, err := VersionsFor("llvm.org", "linux", "aarch64")
	if err != nil {
		t.Fatalf("VersionsFor: %v", err)
	}
	if len(vs) != 3 || vs[0].Raw != "16.0.6" || vs[2].Raw != "20.1.0" {
		t.Fatalf("upstream fallback versions = %v", vs)
	}
	if *hits == 0 {
		t.Error("expected the upstream dist to be consulted")
	}
	// And the build-time constraint form pkgx uses ("<19") selects the highest
	// satisfying version from that fallback list.
	var best Ver
	for _, ver := range vs {
		if ver.satisfies("<19") {
			best = ver
		}
	}
	if best.Raw != "18.1.8" {
		t.Fatalf("highest <19 = %q, want 18.1.8", best.Raw)
	}
}

// TestVersionsForOCINonEmptyShortCircuits: when the OCI registry has versions,
// VersionsFor returns them and never consults the upstream dist.
func TestVersionsForOCINonEmptyShortCircuits(t *testing.T) {
	t.Setenv("PKGX_VERIFY", "0")
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/packages"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Push("acme.org/tool", "2.5.0", "linux", "aarch64", makeGzTarball("x"), ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	up, hits := upstreamVersionsServer(t, "acme.org/tool", "linux", "aarch64", []string{"9.9.9"})
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-pkgx/packages"), up
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()

	vs, err := VersionsFor("acme.org/tool", "linux", "aarch64")
	if err != nil || len(vs) != 1 || vs[0].Raw != "2.5.0" {
		t.Fatalf("OCI versions = %v err=%v", vs, err)
	}
	if *hits != 0 {
		t.Errorf("upstream dist must not be consulted when OCI has versions (hits=%d)", *hits)
	}
}

// TestVersionsForOCIEmptyUpstreamError: a failing upstream dist propagates its
// error through the fallback.
func TestVersionsForOCIEmptyUpstreamError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	fr.mu.Lock()
	fr.tags["go-pkgx/packages/ghost.org"] = map[string]bool{}
	fr.mu.Unlock()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer up.Close()
	oldDist, oldUp := DistBase, UpstreamDist
	DistBase, UpstreamDist = fr.base("go-pkgx/packages"), up.URL
	defer func() { DistBase, UpstreamDist = oldDist, oldUp; resetOCICache() }()
	resetOCICache()
	if _, err := VersionsFor("ghost.org", "linux", "aarch64"); err == nil {
		t.Fatal("expected upstream HTTP error to propagate")
	}
}

// TestVersionsForNonOCIDist: a plain static-HTTP DistBase still lists versions
// directly (no OCI, no fallback).
func TestVersionsForNonOCIDist(t *testing.T) {
	up, _ := upstreamVersionsServer(t, "plain.org", "linux", "aarch64", []string{"1.0.0", "1.1.0"})
	oldDist := DistBase
	DistBase = up // non-oci:// → httpVersionsFor(DistBase, ...)
	defer func() { DistBase = oldDist }()
	vs, err := VersionsFor("plain.org", "linux", "aarch64")
	if err != nil || len(vs) != 2 || vs[1].Raw != "1.1.0" {
		t.Fatalf("non-OCI versions = %v err=%v", vs, err)
	}
}

func TestFetchMeta(t *testing.T) {
	osn, _ := HostSlug()
	yml := "dependencies:\n  dep.org/lib: ^1.1\n  " + osn + ":\n    plat.org/only: '*'\n  win/x:\n    no.org/pe: '*'\nprovides:\n  - bin/tool\n"
	defer fakeServer(t, map[string]fakePkg{"acme.org/tool": {yaml: yml}})()
	deps, provides, err := FetchMeta("acme.org/tool")
	if err != nil {
		t.Fatal(err)
	}
	if deps["dep.org/lib"] != "^1.1" || deps["plat.org/only"] != "*" {
		t.Fatalf("deps = %v", deps)
	}
	if _, ok := deps["no.org/pe"]; ok {
		t.Errorf("non-host platform dep leaked: %v", deps)
	}
	if len(provides) != 1 || provides[0] != "bin/tool" {
		t.Errorf("provides = %v", provides)
	}
}

func TestResolveClosureAndInstall(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "dependencies:\n  dep.org/lib: '*'\nprovides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "#!bin\n", "lib/libx.so": "x"},
		},
		"dep.org/lib": {
			versions: []string{"2.3.0"},
			yaml:     "provides:\n  - bin/lib\n",
			files:    map[string]string{"lib/libdep.so": "d"},
			xzOnly:   false,
		},
	})()
	closure, err := ResolveClosure(map[string]string{"acme.org/tool": "*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure) != 2 {
		t.Fatalf("closure len = %d", len(closure))
	}
	dir := t.TempDir()
	for _, r := range closure {
		fresh, err := Install(r, dir)
		if err != nil || !fresh {
			t.Fatalf("install %s fresh=%v err=%v", r.Project, fresh, err)
		}
	}
	// second install is cached
	if fresh, _ := Install(closure[0], dir); fresh {
		t.Error("expected cached on second install")
	}
	// extracted layout + version symlink
	if _, err := os.Stat(filepath.Join(dir, "acme.org/tool/v1.0.0/bin/tool")); err != nil {
		t.Errorf("missing extracted bin: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "acme.org/tool/v1")); err != nil {
		t.Errorf("missing v1 symlink: %v", err)
	}
	// closure lib path spans both packages
	lp := LibPath(closure, dir)
	if !strings.Contains(lp, "acme.org/tool/v1.0.0/lib") || !strings.Contains(lp, "dep.org/lib/v2.3.0/lib") {
		t.Errorf("libpath = %q", lp)
	}
	// PrefixOf resolves an in-closure project, "" for an absent one.
	if got := PrefixOf("dep.org/lib", closure, dir); got != filepath.Join(dir, "dep.org/lib", "v2.3.0") {
		t.Errorf("PrefixOf in-closure = %q", got)
	}
	if got := PrefixOf("not/here", closure, dir); got != "" {
		t.Errorf("PrefixOf absent = %q, want empty", got)
	}
}

func TestInstallBottleConcurrent(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"acme.org/tool": {
			versions: []string{"1.0.0"},
			yaml:     "provides:\n  - bin/tool\n",
			files:    map[string]string{"bin/tool": "#!x\n", "lib/libx.so": "x"},
		},
	})()
	dir := t.TempDir()
	r := Resolved{"acme.org/tool", ParseVer("1.0.0")}
	// Many workers install the same bottle into one PKGX_DIR at once.
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { _, e := Install(r, dir); errs <- e }()
	}
	for i := 0; i < 12; i++ {
		if e := <-errs; e != nil {
			t.Errorf("concurrent install error: %v", e)
		}
	}
	// exactly one clean prefix, no leftover temp dirs
	if _, err := os.Stat(filepath.Join(dir, "acme.org/tool/v1.0.0/bin/tool")); err != nil {
		t.Errorf("missing extracted bin after concurrent install: %v", err)
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if len(tmps) != 0 {
		t.Errorf("stray temp dirs: %v", tmps)
	}
}

func TestInstallBottleXZFallback(t *testing.T) {
	// gzip 404s -> exercises the .tar.xz branch error path (no xz body served).
	defer fakeServer(t, map[string]fakePkg{
		"xz.org/only": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/only\n", xzOnly: true},
	})()
	_, err := Install(Resolved{"xz.org/only", ParseVer("1.0.0")}, t.TempDir())
	if err == nil {
		t.Fatal("expected error when neither gz nor a valid xz is served")
	}
}

func TestFetchBottleServerError(t *testing.T) {
	t.Setenv("PKGX_VERIFY", "0") // status-code path: an HTTP dist is unverifiable by design
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	old := DistBase
	DistBase = srv.URL
	defer func() { DistBase = old }()
	_, _, err := fetchBottle(Resolved{"a/b", ParseVer("1.0.0")}, "linux", "x86-64")
	if err == nil {
		t.Fatal("want error on 500")
	}
}

func TestHTTPGetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", 404)
	}))
	defer srv.Close()
	if _, err := httpGet(srv.URL); err == nil {
		t.Fatal("want error on 404")
	}
	if _, err := httpGet("http://127.0.0.1:0/bad"); err == nil {
		t.Fatal("want error on dial fail")
	}
}

func TestDirDefault(t *testing.T) {
	// Empty config so PKGX_DIR resolution depends only on the environment.
	setConfigPath(t, filepath.Join(t.TempDir(), "absent.hcl2"))
	t.Setenv("PKGX_DIR", "")
	t.Setenv("HOME", "/tmp/homeX")
	if got := Dir(); got != "/tmp/homeX/.pkgx" {
		t.Errorf("default Dir = %q", got)
	}
	t.Setenv("PKGX_DIR", "/custom")
	if got := Dir(); got != "/custom" {
		t.Errorf("env Dir = %q", got)
	}
}

func TestNewHTTPClient(t *testing.T) {
	if NewHTTPClient() == nil {
		t.Fatal("nil client")
	}
}

func TestPlatformMatches(t *testing.T) {
	if !platformMatches("linux", "linux", "x86-64") {
		t.Error("os match")
	}
	if !platformMatches("linux/x86-64", "linux", "x86-64") {
		t.Error("os/arch match")
	}
	if platformMatches("darwin", "linux", "x86-64") {
		t.Error("should not match")
	}
	if !isPlatformKey("linux/aarch64") || isPlatformKey("openssl.org") {
		t.Error("isPlatformKey")
	}
}

func TestDecodeProvidesScalar(t *testing.T) {
	// a scalar node is neither a list nor a platform map -> nil.
	var n yaml.Node
	if err := yaml.Unmarshal([]byte("just-a-string\n"), &n); err != nil {
		t.Fatal(err)
	}
	if got := decodeProvides(*n.Content[0]); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestDecodeProvidesPlatformMap(t *testing.T) {
	osn, _ := HostSlug()
	var n yaml.Node
	_ = yaml.Unmarshal([]byte(osn+":\n  - bin/x\nother:\n  - bin/y\n"), &n)
	got := decodeProvides(*n.Content[0]) // the mapping node
	if len(got) != 1 || got[0] != "bin/x" {
		t.Errorf("platform provides = %v", got)
	}
}

func TestUntarVariants(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "d/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.WriteHeader(&tar.Header{Name: "d/s", Typeflag: tar.TypeSymlink, Linkname: "f"})
	_ = tw.WriteHeader(&tar.Header{Name: "d/h", Typeflag: tar.TypeLink, Linkname: "d/f"})
	tw.Close()
	if err := untar(&buf, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "d/f")); string(b) != "abc" {
		t.Errorf("reg = %q", b)
	}
	if tgt, _ := os.Readlink(filepath.Join(dest, "d/s")); tgt != "f" {
		t.Errorf("symlink = %q", tgt)
	}
}

func TestUntarUnsafePath(t *testing.T) {
	dest := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Size: 1})
	_, _ = tw.Write([]byte("x"))
	tw.Close()
	if err := untar(&buf, dest); err == nil {
		t.Fatal("expected unsafe-path error")
	}
}

// TestPantryOverlay: a recipe present in the overlay is served from there; one
// absent from the overlay falls back to PantryBase.
func TestPantryOverlay(t *testing.T) {
	osn, _ := HostSlug()
	overridden := "dependencies:\n  openssl.org: '*'\nprovides:\n  - bin/curl\n"
	upstream := "dependencies:\n  openssl.org: ^1.1\nprovides:\n  - bin/curl\n"
	base := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/curl.se/package.yml":
			fmt.Fprint(w, upstream)
		case "/zlib.net/package.yml":
			fmt.Fprint(w, "provides:\n  - lib/libz."+osn+"\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer base.Close()
	overlay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/curl.se/package.yml" {
			fmt.Fprint(w, overridden)
			return
		}
		http.NotFound(w, r) // overlay only carries curl.se
	}))
	defer overlay.Close()

	ob, op := PantryBase, PantryOverlay
	defer func() { PantryBase, PantryOverlay = ob, op }()
	PantryBase, PantryOverlay = base.URL, overlay.URL

	// overlay hit -> corrected constraint
	deps, _, err := FetchMeta("curl.se")
	if err != nil || deps["openssl.org"] != "*" {
		t.Fatalf("overlay hit: deps=%v err=%v (want openssl.org=*)", deps, err)
	}
	// overlay miss -> fall back to base (must still resolve)
	if _, _, err := FetchMeta("zlib.net"); err != nil {
		t.Fatalf("overlay miss fallback: %v", err)
	}
	// with no overlay, base is used verbatim
	PantryOverlay = ""
	deps, _, err = FetchMeta("curl.se")
	if err != nil || deps["openssl.org"] != "^1.1" {
		t.Fatalf("no overlay: deps=%v err=%v (want openssl.org=^1.1)", deps, err)
	}
}

func TestApplyEnvOverlay(t *testing.T) {
	ob := PantryOverlay
	defer func() { PantryOverlay = ob }()
	PantryOverlay = ""
	applyEnv(func(k string) string {
		if k == "PKGX_PANTRY_OVERLAY" {
			return "https://ov.example/projects/"
		}
		return ""
	})
	if PantryOverlay != "https://ov.example/projects" {
		t.Errorf("PantryOverlay = %q", PantryOverlay)
	}
}

// TestFetchRuntimeEnv: a package declaring `runtime: env:` is declaring what its
// CONSUMERS need. help2man bundles the perl module Locale::gettext into its own
// prefix and publishes PERL5LIB so it is findable; without that export it dies
// with "Can't locate Locale/gettext.pm in @INC", which is exactly how
// gnu.org/libidn2 failed to build.
func TestFetchRuntimeEnv(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"gnu.org/help2man": {
			versions: []string{"1.49.3"},
			yaml: "runtime:\n  env:\n    PERL5LIB: \"{{prefix}}/lib/perl5:{{prefix}}/libexec/lib/perl5:$PERL5LIB\"\n" +
				"    MAJOR: \"{{version.major}}.{{ version.minor }}\"\nprovides:\n  - bin/help2man\n",
		},
		"plain.org": {versions: []string{"1.0.0"}, yaml: "provides:\n  - bin/plain\n"},
	})()

	env, err := FetchRuntimeEnv("gnu.org/help2man", "/pkgx/gnu.org/help2man/v1.49.3", "1.49.3")
	if err != nil {
		t.Fatal(err)
	}
	want := "/pkgx/gnu.org/help2man/v1.49.3/lib/perl5:/pkgx/gnu.org/help2man/v1.49.3/libexec/lib/perl5:$PERL5LIB"
	if env["PERL5LIB"] != want {
		t.Errorf("PERL5LIB = %q\nwant %q", env["PERL5LIB"], want)
	}
	// the shell reference survives expansion: the value chains onto whatever the
	// caller already had, which is how two packages both contribute to one var.
	if !strings.Contains(env["PERL5LIB"], "$PERL5LIB") {
		t.Error("the $VAR chain must be preserved verbatim for the shell")
	}
	if env["MAJOR"] != "1.49" {
		t.Errorf("version parts = %q, want 1.49", env["MAJOR"])
	}
	// a package with no runtime env yields an empty map, not an error
	if env, err := FetchRuntimeEnv("plain.org", "/p", "1.0.0"); err != nil || len(env) != 0 {
		t.Errorf("plain package: env=%v err=%v", env, err)
	}
	// an unserved project is an error
	if _, err := FetchRuntimeEnv("absent.org", "/p", "1.0.0"); err == nil {
		t.Error("expected an error for an unserved project")
	}
}

func TestExpandRecipeVars(t *testing.T) {
	for in, want := range map[string]string{
		"{{prefix}}/lib":         "/p/lib",
		"{{ prefix }}/lib":       "/p/lib",
		"v{{version}}":           "v2.3.4",
		"v{{ version.raw }}":     "v2.3.4",
		"{{version.marketing}}":  "2.3",
		"{{version.major}}":      "2",
		"{{version.minor}}":      "3",
		"a{{ hw.concurrency }}b": "ab", // unknown at install time: dropped, never literal
		"nothing":                "nothing",
	} {
		if got := expandRecipeVars(in, "/p", "2.3.4"); got != want {
			t.Errorf("expandRecipeVars(%q) = %q, want %q", in, got, want)
		}
	}
	// a version with fewer components still answers for the parts asked of it
	if got := expandRecipeVars("{{version.minor}}", "/p", "7"); got != "0" {
		t.Errorf("missing component = %q, want 0", got)
	}
}

// A malformed recipe is an error, not silently no env.
func TestFetchRuntimeEnvBadYAML(t *testing.T) {
	defer fakeServer(t, map[string]fakePkg{
		"bad.org": {versions: []string{"1.0.0"}, yaml: "runtime:\n  env: [this is not a map]\n"},
	})()
	if _, err := FetchRuntimeEnv("bad.org", "/p", "1.0.0"); err == nil {
		t.Error("expected a parse error")
	}
}
