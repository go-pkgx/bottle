package bottle

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// crossPantry serves a pantry + dist for ONE explicit platform slug, so a test
// can resolve for a platform that is not the host's. fakeServer answers only
// under HostSlug(), which is exactly the assumption these functions exist to
// break.
//
// versions maps "<project>/<os>/<arch>" to the published version list, so the
// same project can exist on one platform and be absent on another.
func crossPantry(t *testing.T, recipes map[string]string, versions map[string][]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if proj, ok := strings.CutSuffix(p, "/package.yml"); ok {
			y, ok := recipes[proj]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, y)
			return
		}
		if key, ok := strings.CutSuffix(p, "/versions.txt"); ok {
			vs, ok := versions[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, strings.Join(vs, "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	oldPantry, oldUp := PantryBase, UpstreamDist
	PantryBase, UpstreamDist = srv.URL, srv.URL
	withDist(t, srv.URL)
	return func() {
		PantryBase, UpstreamDist = oldPantry, oldUp
		srv.Close()
	}
}

// TestPickVersionForOtherPlatform: a project can be published for one platform
// and absent from another. Resolving through the host's slug would either miss
// the version or pick a different one.
func TestPickVersionForOtherPlatform(t *testing.T) {
	hostOS, hostArch := HostSlug()
	defer crossPantry(t,
		map[string]string{"x.org/tool": "provides:\n  - bin/tool\n"},
		map[string][]string{
			"x.org/tool/linux/x86-64": {"1.0.0", "2.4.0"},
			// nothing under the host slug on purpose
		})()

	v, err := PickVersionFor("x.org/tool", "*", "linux", "x86-64")
	if err != nil {
		t.Fatalf("PickVersionFor(linux/x86-64): %v", err)
	}
	if v.Raw != "2.4.0" {
		t.Errorf("picked %q, want the highest linux version 2.4.0", v.Raw)
	}
	if _, err := PickVersionFor("x.org/tool", "*", hostOS, hostArch); err == nil {
		t.Errorf("host slug %s/%s resolved a version the pantry publishes only for linux/x86-64", hostOS, hostArch)
	}
}

// TestFetchMetaForPlatformKeyedDeps: recipes key their dependencies by
// platform. Reading them through the host's slug while staging another
// platform's rootfs yields the wrong closure — silently, since both answers
// are well-formed.
func TestFetchMetaForPlatformKeyedDeps(t *testing.T) {
	recipe := "dependencies:\n" +
		"  common.org/lib: '*'\n" +
		"  linux:\n" +
		"    linux.org/only: '*'\n" +
		"  darwin:\n" +
		"    darwin.org/only: '*'\n" +
		"provides:\n  - bin/tool\n"
	defer crossPantry(t, map[string]string{"x.org/tool": recipe}, nil)()

	deps, provides, err := FetchMetaFor("x.org/tool", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps["linux.org/only"]; !ok {
		t.Errorf("linux-only dependency missing: %v", deps)
	}
	if _, ok := deps["darwin.org/only"]; ok {
		t.Errorf("darwin-only dependency leaked into a linux closure: %v", deps)
	}
	if _, ok := deps["common.org/lib"]; !ok {
		t.Errorf("unkeyed dependency dropped: %v", deps)
	}
	if len(provides) != 1 || provides[0] != "bin/tool" {
		t.Errorf("provides = %v", provides)
	}

	// The same recipe, read for darwin, must give the mirror answer — proving
	// the slug is what selects, not some ambient default.
	deps, _, err = FetchMetaFor("x.org/tool", "darwin", "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps["darwin.org/only"]; !ok {
		t.Errorf("darwin-only dependency missing: %v", deps)
	}
	if _, ok := deps["linux.org/only"]; ok {
		t.Errorf("linux-only dependency leaked into a darwin closure: %v", deps)
	}
}

// TestResolveClosureForWalksTargetPlatform is the end of the chain: the whole
// walk — version picks and dependency reads — must happen in the target's
// terms. This is what lets a darwin machine stage a linux/aarch64 userland.
func TestResolveClosureForWalksTargetPlatform(t *testing.T) {
	defer crossPantry(t,
		map[string]string{
			"x.org/tool": "dependencies:\n" +
				"  linux:\n    linux.org/only: '*'\n" +
				"  darwin:\n    darwin.org/only: '*'\n" +
				"provides:\n  - bin/tool\n",
			"linux.org/only":  "provides:\n  - lib/liblinux.so\n",
			"darwin.org/only": "provides:\n  - lib/libdarwin.dylib\n",
		},
		map[string][]string{
			"x.org/tool/linux/aarch64":      {"1.0.0"},
			"linux.org/only/linux/aarch64":  {"3.1.0"},
			"darwin.org/only/linux/aarch64": {"9.9.9"}, // published, but must not be pulled in
		})()

	clo, err := ResolveClosureFor(map[string]string{"x.org/tool": "*"}, "linux", "aarch64")
	if err != nil {
		t.Fatalf("ResolveClosureFor: %v", err)
	}

	got := map[string]string{}
	for _, r := range clo {
		got[r.Project] = r.Version.Raw
	}
	if got["x.org/tool"] != "1.0.0" || got["linux.org/only"] != "3.1.0" {
		t.Errorf("closure = %v, want tool 1.0.0 + linux.org/only 3.1.0", got)
	}
	if _, ok := got["darwin.org/only"]; ok {
		t.Errorf("darwin branch walked while staging linux: %v", got)
	}
	if len(clo) != 2 {
		t.Errorf("closure has %d entries, want 2: %v", len(clo), got)
	}
}

// TestResolveClosureForPropagatesErrors keeps the failure modes explicit: an
// unresolvable version and an unreadable recipe must both stop the walk rather
// than yield a partial rootfs.
func TestResolveClosureForPropagatesErrors(t *testing.T) {
	defer crossPantry(t,
		map[string]string{
			"x.org/tool": "dependencies:\n  gone.org/dep: '*'\nprovides:\n  - bin/tool\n",
			"v.org/tool": "provides:\n  - bin/tool\n",
		},
		map[string][]string{
			"x.org/tool/linux/aarch64": {"1.0.0"},
			"v.org/tool/linux/aarch64": {"1.0.0"},
		})()

	if _, err := ResolveClosureFor(map[string]string{"x.org/tool": "*"}, "linux", "aarch64"); err == nil {
		t.Error("a dependency with no published version must fail the closure")
	}
	if _, err := ResolveClosureFor(map[string]string{"v.org/tool": "^9"}, "linux", "aarch64"); err == nil {
		t.Error("an unsatisfiable root constraint must fail the closure")
	}
}
