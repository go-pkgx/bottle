package bottle

import (
	"os"
	"path/filepath"
	"testing"
)

// links reads back every alias in a project directory.
func links(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		tgt, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = tgt
	}
	return out
}

func installDir(t *testing.T, pkgxDir, project, raw string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(pkgxDir, project, "v"+raw, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// Installing an OLDER line beside a newer one must not demote v* or v<major>
// onto it. Every consumer still bound to v2 would load the older library —
// the failure the ABI lines exist to end, reached from the other side.
func TestVersionAliasDoesNotRegress(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "gnome.org/libxml2"
	installDir(t, pkgx, proj, "2.15.4")
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.15.4")})
	installDir(t, pkgx, proj, "2.13.9")
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.13.9")})

	got := links(t, filepath.Join(pkgx, proj))
	for alias, want := range map[string]string{
		"v*":    "v2.15.4", // the newest, not the last installed
		"v2":    "v2.15.4",
		"v2.15": "v2.15.4",
		"v2.13": "v2.13.9", // its own minor line, which only 2.13.x can claim
	} {
		if got[alias] != want {
			t.Errorf("%s -> %s, want %s (all: %v)", alias, got[alias], want, got)
		}
	}
}

// The ordinary direction still works: a newer version takes the aliases.
func TestVersionAliasAdvances(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "a.org"
	installDir(t, pkgx, proj, "1.0.0")
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")})
	installDir(t, pkgx, proj, "2.0.0")
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.0.0")})

	got := links(t, filepath.Join(pkgx, proj))
	if got["v*"] != "v2.0.0" || got["v1"] != "v1.0.0" || got["v2"] != "v2.0.0" {
		t.Errorf("aliases = %v", got)
	}
}

// A DANGLING alias is worse than a stale one: nothing resolves through it. So
// an alias naming a version that is no longer installed is taken over, even by
// an older one.
func TestVersionAliasTakesOverADanglingLink(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "a.org"
	dir := filepath.Join(pkgx, proj)
	installDir(t, pkgx, proj, "1.0.0")
	if err := os.Symlink("v9.9.9", filepath.Join(dir, "v*")); err != nil {
		t.Fatal(err)
	}
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")})

	if got := links(t, dir); got["v*"] != "v1.0.0" {
		t.Errorf("v* -> %s, want the installed version (all: %v)", got["v*"], got)
	}
}

// Something that is not one of our version links is replaced rather than
// reasoned about: it is not an alias this function wrote.
func TestVersionAliasReplacesSomethingUnreadable(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "a.org"
	dir := filepath.Join(pkgx, proj)
	installDir(t, pkgx, proj, "1.0.0")
	if err := os.Symlink("somewhere-else", filepath.Join(dir, "v*")); err != nil {
		t.Fatal(err)
	}
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")})

	if got := links(t, dir); got["v*"] != "v1.0.0" {
		t.Errorf("v* -> %s (all: %v)", got["v*"], got)
	}
}
