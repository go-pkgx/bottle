package bottle

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// withGlibcEnv points Env at a fixed map (no ~/.pkgx/config.hcl2, no real
// process environment) and clears the memoised glibc constraint.
func withGlibcEnv(t *testing.T, m map[string]string) {
	t.Helper()
	oldLookup, oldPath := lookupEnv, configPathFn
	lookupEnv = func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	configPathFn = func() (string, error) { return filepath.Join(t.TempDir(), "absent.hcl2"), nil }
	reloadConfig()
	resetGlibcConstraint()
	t.Cleanup(func() {
		lookupEnv, configPathFn = oldLookup, oldPath
		reloadConfig()
		resetGlibcConstraint()
	})
}

// withKernel makes the host look like linux running the given kernel release.
func withKernel(t *testing.T, release string) {
	t.Helper()
	setGoos(t, "linux")
	setGoarch(t, "x86-64")
	p := filepath.Join(t.TempDir(), "osrelease")
	if err := os.WriteFile(p, []byte(release+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := osReleasePath
	osReleasePath = p
	t.Cleanup(func() { osReleasePath = old })
}

// withGlibcVersions serves a static pkgx dist listing those glibc versions.
func withGlibcVersions(t *testing.T, versions ...string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/versions.txt") {
			fmt.Fprintln(w, strings.Join(versions, "\n"))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	withDist(t, srv.URL)
}

// withMinKernels stubs the registry annotation lookup: version → floor
// ("" = the bottle records no floor).
func withMinKernels(t *testing.T, floors map[string]string) {
	t.Helper()
	old := glibcMinKernelOf
	glibcMinKernelOf = func(ver, _, _ string) (string, error) {
		mk, ok := floors[ver]
		if !ok {
			return "", errors.New("no such glibc")
		}
		return mk, nil
	}
	t.Cleanup(func() { glibcMinKernelOf = old })
}

func TestSplitFlavor(t *testing.T) {
	for _, tc := range []struct{ tag, version, glibc string }{
		{"8.20.0", "8.20.0", ""},
		{"8.20.0-glibc2.27.0", "8.20.0", "2.27.0"},
		{"1.2.3-rc1-glibc2.44.0", "1.2.3-rc1", "2.44.0"},
		{"-glibc2.27.0", "-glibc2.27.0", ""}, // no version part: not a flavor
		{"", "", ""},
	} {
		v, g := SplitFlavor(tc.tag)
		if v != tc.version || g != tc.glibc {
			t.Errorf("SplitFlavor(%q) = %q, %q; want %q, %q", tc.tag, v, g, tc.version, tc.glibc)
		}
	}
}

func TestHostKernel(t *testing.T) {
	t.Run("linux", func(t *testing.T) {
		withKernel(t, "6.8.0-45-generic")
		got, err := HostKernel()
		if err != nil || got != "6.8.0-45-generic" {
			t.Fatalf("HostKernel = %q, %v", got, err)
		}
	})
	t.Run("not linux", func(t *testing.T) {
		setGoos(t, "darwin")
		got, err := HostKernel()
		if err != nil || got != "" {
			t.Fatalf("HostKernel = %q, %v", got, err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		setGoos(t, "linux")
		old := osReleasePath
		osReleasePath = filepath.Join(t.TempDir(), "absent")
		t.Cleanup(func() { osReleasePath = old })
		if _, err := HostKernel(); err == nil {
			t.Fatal("want an error")
		}
	})
}

// TestGlibcConstraintPin: PKGX_GLIBC pins an exact glibc (with or without the
// leading '='), and the answer is memoised.
func TestGlibcConstraintPin(t *testing.T) {
	for _, pin := range []string{"2.27.0", "=2.27.0", " 2.27.0 "} {
		withGlibcEnv(t, map[string]string{"PKGX_GLIBC": pin})
		if got := GlibcConstraint(); got != "=2.27.0" {
			t.Fatalf("PKGX_GLIBC=%q → %q", pin, got)
		}
	}
	// memoised: a later change to the environment does not re-resolve
	withGlibcEnv(t, map[string]string{"PKGX_GLIBC": "2.27.0"})
	_ = GlibcConstraint()
	lookupEnv = func(string) (string, bool) { return "2.44.0", true }
	if got := GlibcConstraint(); got != "=2.27.0" {
		t.Fatalf("constraint re-resolved: %q", got)
	}
}

// TestGlibcConstraintFallsBackToNewest: with no pin and nothing to compare
// against, resolution is left exactly as it was ("*").
func TestGlibcConstraintFallsBackToNewest(t *testing.T) {
	t.Run("not linux", func(t *testing.T) {
		withGlibcEnv(t, nil)
		setGoos(t, "darwin")
		if got := GlibcConstraint(); got != "*" {
			t.Fatalf("constraint = %q", got)
		}
	})
	t.Run("kernel unreadable", func(t *testing.T) {
		withGlibcEnv(t, nil)
		setGoos(t, "linux")
		old := osReleasePath
		osReleasePath = filepath.Join(t.TempDir(), "absent")
		t.Cleanup(func() { osReleasePath = old })
		if got := GlibcConstraint(); got != "*" {
			t.Fatalf("constraint = %q", got)
		}
	})
}

// TestGlibcSelectionByKernel is the headline behaviour: the newest glibc the
// running kernel can actually run is chosen, and ONLY when the newest one
// cannot run here.
func TestGlibcSelectionByKernel(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kernel   string
		versions []string
		floors   map[string]string
		want     string
	}{
		{
			name:     "newest fits — nothing to change",
			kernel:   "6.8.0-45-generic",
			versions: []string{"2.27.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.44.0": "3.2.0"},
			want:     "*",
		},
		{
			name:     "old kernel: the newest glibc's floor is too high",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.38.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.38.0": "3.2.0", "2.44.0": "4.19.0"},
			want:     "=2.38.0",
		},
		{
			name:     "nothing published fits — leave it alone",
			kernel:   "2.6.32-696.el6.x86_64",
			versions: []string{"2.38.0", "2.44.0"},
			floors:   map[string]string{"2.38.0": "3.2.0", "2.44.0": "4.19.0"},
			want:     "*",
		},
		{
			name:     "newest records no floor — cannot vouch, so do not downgrade",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.44.0": ""},
			want:     "*",
		},
		{
			name:     "an intermediate with no floor is skipped, not guessed at",
			kernel:   "3.10.0-1160.el7.x86_64",
			versions: []string{"2.27.0", "2.38.0", "2.44.0"},
			floors:   map[string]string{"2.27.0": "3.2.0", "2.38.0": "", "2.44.0": "4.19.0"},
			want:     "=2.27.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGlibcEnv(t, nil)
			withKernel(t, tc.kernel)
			withGlibcVersions(t, tc.versions...)
			withMinKernels(t, tc.floors)
			if got := GlibcConstraint(); got != tc.want {
				t.Fatalf("constraint = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGlibcSelectionVersionListingFails: an unreachable dist must not break
// closure resolution — it falls back to "*".
func TestGlibcSelectionVersionListingFails(t *testing.T) {
	withGlibcEnv(t, nil)
	withKernel(t, "3.10.0-1160.el7.x86_64")
	withDist(t, "https://127.0.0.1:1/dist")
	if got := GlibcConstraint(); got != "*" {
		t.Fatalf("constraint = %q", got)
	}
}

// TestImplicitRootsUsesGlibcConstraint proves the selector actually reaches
// closure completion (where every dynamic ELF gets its loader + libc).
func TestImplicitRootsUsesGlibcConstraint(t *testing.T) {
	withGlibcEnv(t, map[string]string{"PKGX_GLIBC": "2.27.0"})
	if got := implicitRoots(nil)[GlibcProject]; got != "=2.27.0" {
		t.Fatalf("glibc root = %q", got)
	}
}

// TestGlibcMinKernelOf covers the real annotation reader against a registry.
func TestGlibcMinKernelOf(t *testing.T) {
	t.Run("static dist has no annotations", func(t *testing.T) {
		withDist(t, "https://dist.example.test")
		mk, err := glibcMinKernelOf("2.44.0", "linux", "x86-64")
		if err != nil || mk != "" {
			t.Fatalf("mk = %q, err = %v", mk, err)
		}
	})
	t.Run("unusable registry", func(t *testing.T) {
		withDist(t, "oci://hostonly")
		if _, err := glibcMinKernelOf("2.44.0", "linux", "x86-64"); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("published glibc", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		withDist(t, fr.base("go-pkgx/bottles"))
		c, err := NewOCIClient(DistBase)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.PushWithReferrersAnnotated(GlibcProject, "2.44.0", "linux", "x86-64",
			makeGzTarball("libc"), ExtTarGz, nil,
			map[string]string{GlibcMinKernelAnnotation: "3.2.0"}); err != nil {
			t.Fatal(err)
		}
		mk, err := glibcMinKernelOf("2.44.0", "linux", "x86-64")
		if err != nil || mk != "3.2.0" {
			t.Fatalf("mk = %q, err = %v", mk, err)
		}
		// an unpublished version is a real lookup failure, not a silent ""
		if _, err := glibcMinKernelOf("9.9.9", "linux", "x86-64"); err == nil {
			t.Fatal("want an error for an unpublished glibc")
		}
	})
}

// TestOCIClientAnnotations covers the accessor's error paths.
func TestOCIClientAnnotations(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/bottles"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Annotations("BAD..name/../x", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for a bad project")
	}
	if _, err := c.Annotations("absent.test", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("want an error for an unpublished version")
	}
}

// TestOCIVersionsSkipFlavoredTags: a glibc-flavored tag must never be picked as
// a version of its own — it would otherwise outrank the tag it flavors.
func TestOCIVersionsSkipFlavoredTags(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	withDist(t, fr.base("go-pkgx/bottles"))
	c, err := NewOCIClient(DistBase)
	if err != nil {
		t.Fatal(err)
	}
	repo := c.repoName("curl.se")
	for _, tag := range []string{"8.19.0", "8.20.0", "8.20.0-glibc2.27.0"} {
		fr.injectManifest(repo, tag, ocispec.MediaTypeImageManifest, []byte("{}"))
	}
	vs, err := VersionsFor("curl.se", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	var raw []string
	for _, v := range vs {
		raw = append(raw, v.Raw)
	}
	if strings.Join(raw, ",") != "8.19.0,8.20.0" {
		t.Fatalf("versions = %v", raw)
	}
	picked, err := PickVersion("curl.se", "*")
	if err != nil || picked.Raw != "8.20.0" {
		t.Fatalf("PickVersion = %q, %v", picked.Raw, err)
	}
}
