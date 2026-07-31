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
