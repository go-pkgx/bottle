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

// installDir makes the REAL directory an install would make: hashed.
//
// ⛔ THE ALIASES NOW POINT AT IT, NOT AT `v<raw>`. `v<raw>` is itself a
// symlink, and for a two-component version like "1.2" the `v{maj}.{min}`
// alias IS `v1.2` — so targeting `v<raw>` wrote `v1.2 -> v1.2`, a
// self-symlink that replaced the real alias and left the version
// unresolvable. These tests assert the target, so they are what notices.
func installDir(t *testing.T, pkgxDir, project, raw string) string {
	t.Helper()
	hash := StoreHash(ParseVer(raw), "digest:"+project+"@"+raw, "")
	if err := os.MkdirAll(filepath.Join(pkgxDir, project, StoreBuildDirName(ParseVer(raw), hash), "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	return hash
}

// dirOf is the hashed directory installDir made, for an expectation.
func dirOf(project, raw string) string {
	return StoreBuildDirName(ParseVer(raw), StoreHash(ParseVer(raw), "digest:"+project+"@"+raw, ""))
}

// Installing an OLDER line beside a newer one must not demote v* or v<major>
// onto it. Every consumer still bound to v2 would load the older library —
// the failure the ABI lines exist to end, reached from the other side.
func TestVersionAliasDoesNotRegress(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "gnome.org/libxml2"
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.15.4")}, installDir(t, pkgx, proj, "2.15.4"))
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.13.9")}, installDir(t, pkgx, proj, "2.13.9"))

	got := links(t, filepath.Join(pkgx, proj))
	for alias, want := range map[string]string{
		"v*":    dirOf(proj, "2.15.4"), // the newest, not the last installed
		"v2":    dirOf(proj, "2.15.4"),
		"v2.15": dirOf(proj, "2.15.4"),
		"v2.13": dirOf(proj, "2.13.9"), // its own minor line, which only 2.13.x can claim
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
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")}, installDir(t, pkgx, proj, "1.0.0"))
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("2.0.0")}, installDir(t, pkgx, proj, "2.0.0"))

	got := links(t, filepath.Join(pkgx, proj))
	if got["v*"] != dirOf(proj, "2.0.0") || got["v1"] != dirOf(proj, "1.0.0") || got["v2"] != dirOf(proj, "2.0.0") {
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
	hash := installDir(t, pkgx, proj, "1.0.0")
	if err := os.Symlink("v9.9.9", filepath.Join(dir, "v*")); err != nil {
		t.Fatal(err)
	}
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")}, hash)

	if got := links(t, dir); got["v*"] != dirOf(proj, "1.0.0") {
		t.Errorf("v* -> %s, want the installed version (all: %v)", got["v*"], got)
	}
}

// Something that is not one of our version links is replaced rather than
// reasoned about: it is not an alias this function wrote.
func TestVersionAliasReplacesSomethingUnreadable(t *testing.T) {
	pkgx := t.TempDir()
	const proj = "a.org"
	dir := filepath.Join(pkgx, proj)
	hash := installDir(t, pkgx, proj, "1.0.0")
	if err := os.Symlink("somewhere-else", filepath.Join(dir, "v*")); err != nil {
		t.Fatal(err)
	}
	writeVersionLinks(pkgx, Resolved{proj, ParseVer("1.0.0")}, hash)

	if got := links(t, dir); got["v*"] != dirOf(proj, "1.0.0") {
		t.Errorf("v* -> %s (all: %v)", got["v*"], got)
	}
}
