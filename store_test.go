package bottle

import (
	"os"
	"path/filepath"
	"testing"
)

// A STORE, BUILT THE WAY THE INSTALLER BUILDS ONE: version directories, the
// alias symlinks writeVersionLinks puts beside them, a nested namespace, and
// the dot-directory a scratch image stages in.
func storeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(path string, n int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, make([]byte, n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "llvm.org", "v22.1.8", "bin", "clang"), 800)
	write(filepath.Join(dir, "llvm.org", "v16.0.6", "bin", "clang"), 300)
	// A NAMESPACE INSIDE A NAMESPACE: gnu.org holds bash, which holds the
	// versions. A scan that only looked one level down would miss every
	// project whose name has a slash in it, which is most of this pantry.
	write(filepath.Join(dir, "gnu.org", "bash", "v5.3", "bin", "bash"), 100)
	write(filepath.Join(dir, "gnu.org", "bash", "v5.10", "bin", "bash"), 150)
	// The staging directory a FROM scratch image needs. Not a project.
	//
	// VERSION-SHAPED ON PURPOSE. The obvious fixture — `.local/tmp/junk` —
	// does not discriminate: nothing under it looks like a version, so the
	// scan finds nothing there whether the skip exists or not, and mutating
	// the skip away leaves the suite green. A half-downloaded bottle in the
	// staging tree looks exactly like this.
	write(filepath.Join(dir, ".local", "tmp", "v9.9", "bin", "half-downloaded"), 9999)
	// The aliases. All three point at the same tree.
	for _, alias := range []string{"v*", "v22", "v22.1"} {
		if err := os.Symlink("v22.1.8", filepath.Join(dir, "llvm.org", alias)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A SYMLINK IS NEVER A VERSION. writeVersionLinks puts `v*`, `v22` and
// `v22.1` beside `v22.1.8`, all pointing at it — 118 such aliases on this
// developer's machine — and following them would report llvm.org four times
// and the store at several times its size.
func TestScanStoreCountsEachVersionOnce(t *testing.T) {
	es, err := ScanStore(storeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, e := range es {
		key := e.Project + "@" + e.Version
		if _, dup := got[key]; dup {
			t.Errorf("%s reported twice", key)
		}
		got[key] = e.Bytes
	}
	want := map[string]int64{
		"llvm.org@22.1.8":  800,
		"llvm.org@16.0.6":  300,
		"gnu.org/bash@5.3": 100,
		// The nested namespace is found, which a one-level scan would miss.
		"gnu.org/bash@5.10": 150,
	}
	if len(got) != len(want) {
		t.Errorf("scanned %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d bytes, want %d", k, got[k], v)
		}
	}
}

// THE DOT-DIRECTORY IS NOT A PROJECT. `.local/tmp` is where a scratch image
// stages a download, and counting it would put 9999 bytes of nobody's
// package in the total.
func TestScanStoreSkipsTheStagingDirectory(t *testing.T) {
	es, err := ScanStore(storeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.Project == ".local" || e.Bytes == 9999 {
			t.Errorf("the staging directory was counted: %+v", e)
		}
	}
}

// NEWEST IS BY VERSION, NOT BY STRING. 5.10 is newer than 5.3, and sorting
// as text says the opposite — the defect this family has already had once,
// in the version picker.
func TestNewestIsTheHighestVersionPresent(t *testing.T) {
	es, err := ScanStore(storeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	newest := map[string]string{}
	for _, e := range es {
		if e.Newest {
			if prev, dup := newest[e.Project]; dup {
				t.Errorf("%s has two newest: %s and %s", e.Project, prev, e.Version)
			}
			newest[e.Project] = e.Version
		}
	}
	if newest["gnu.org/bash"] != "5.10" {
		t.Errorf("newest bash = %q, want 5.10 — string order would say 5.3", newest["gnu.org/bash"])
	}
	if newest["llvm.org"] != "22.1.8" {
		t.Errorf("newest llvm = %q, want 22.1.8", newest["llvm.org"])
	}
}

// THE TOTALS, and the one that is easy to misread: bytes held by versions
// that are not the newest present. A FACT about the disk — not a deletion
// list, because whether an older version can go depends on roots this
// package cannot see.
func TestStoreTotals(t *testing.T) {
	es, err := ScanStore(storeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	bytes, versions, projects, older := StoreTotals(es)
	if bytes != 1350 {
		t.Errorf("bytes = %d, want 1350", bytes)
	}
	if versions != 4 || projects != 2 {
		t.Errorf("%d versions over %d projects, want 4 over 2", versions, projects)
	}
	// 300 (llvm 16.0.6) + 100 (bash 5.3); the two newest are excluded.
	if older != 400 {
		t.Errorf("older = %d, want 400", older)
	}
}

// AN EMPTY STORE IS AN ANSWER, not an error: it is the state of every fresh
// machine, and a command that failed there would be reporting a problem
// that does not exist.
func TestScanStoreOfAnEmptyDirectory(t *testing.T) {
	es, err := ScanStore(t.TempDir())
	if err != nil {
		t.Fatalf("an empty store is not an error: %v", err)
	}
	if len(es) != 0 {
		t.Errorf("found %d entries in an empty store", len(es))
	}
	b, v, p, older := StoreTotals(es)
	if b != 0 || v != 0 || p != 0 || older != 0 {
		t.Errorf("totals of nothing = %d %d %d %d", b, v, p, older)
	}
}

// A STORE THAT IS NOT THERE is a different thing from one that is empty,
// and the caller needs to tell them apart to print the right sentence.
func TestScanStoreOfAnAbsentDirectory(t *testing.T) {
	if _, err := ScanStore(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("an absent store returned no error")
	}
}
