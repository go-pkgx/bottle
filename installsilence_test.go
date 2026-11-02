package bottle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ⛔⛔ "ALREADY INSTALLED" MUST MEAN THE REQUESTED PREFIX IS THERE.
//
// InstallFor renames the unpacked tree onto `dest`, the directory the BOTTLE
// carries — which is not always the version that was requested. A rebuild is
// published as `3.3.11_1` and still unpacks to `v3.3.11`.
//
// So installing a rebuild into a store that already held `v3.3.11` renamed
// onto an occupied directory, took the concurrent-install branch, and
// returned (false, nil): "already installed". Nothing was installed. The
// caller then ran a binary under a prefix that had never been created and
// got a bare "no such file or directory" — go-pkgx/bk#386, found on the
// first real use of the rebuild counter.
//
// Measured before the fix, against the published fftw.org 3.3.11_1:
//
//	Install         -> fresh=false err=<nil>
//	stat(v3.3.11_1) -> no such file or directory
//
// This test drives the same branch without a registry: the rename fails
// because `dest` exists, and the question is only what gets reported.
func TestInstallDoesNotClaimSuccessForAPrefixItDidNotCreate(t *testing.T) {
	dir := t.TempDir()
	// The directory the bottle would carry, already occupied by other content
	// — exactly the store of someone holding the un-rebuilt bottle.
	occupied := filepath.Join(dir, "acme.org", "v1.2.3")
	if err := os.MkdirAll(occupied, 0o755); err != nil {
		t.Fatal(err)
	}

	// A prefix the caller asked for that does NOT exist, and a dest that does.
	prefix := filepath.Join(dir, "acme.org", "v1.2.3_1")
	_, err := renameOrExplain(filepath.Join(dir, "nonexistent-src"), occupied, prefix, "acme.org", "1.2.3_1")
	if err == nil {
		t.Fatal("a bottle that was not installed was reported as already installed")
	}
	for _, want := range []string{"v1.2.3", "v1.2.3_1", "not installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// AND A GENUINE CONCURRENT INSTALL IS STILL SILENT. The other worker leaves
// the requested prefix behind, so asking about it separates "somebody else
// did this" from "this did not happen". Without this the fix would turn
// every concurrent install into a failure.
func TestAGenuineConcurrentInstallIsStillReportedAsAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "acme.org", "v1.2.3")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// The other worker created the requested prefix too.
	fresh, err := renameOrExplain(filepath.Join(dir, "nonexistent-src"), dest, dest, "acme.org", "1.2.3")
	if err != nil {
		t.Fatalf("a concurrent install was reported as a failure: %v", err)
	}
	if fresh {
		t.Error("a concurrent install was reported as fresh")
	}
}
