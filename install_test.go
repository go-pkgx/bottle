package bottle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergeClosures(t *testing.T) {
	a := []Resolved{{"a/x", ParseVer("1")}, {"b/y", ParseVer("2")}}
	b := []Resolved{{"b/y", ParseVer("2")}, {"c/z", ParseVer("3")}}
	got := MergeClosures(a, b)
	if len(got) != 3 {
		t.Fatalf("merged len=%d want 3", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.Project] {
			t.Errorf("duplicate project %s", r.Project)
		}
		seen[r.Project] = true
	}
}

func TestFindClosureBin(t *testing.T) {
	dir := t.TempDir()
	closure := []Resolved{{"gnu.org/bash", ParseVer("5.3.0")}}
	binDir := filepath.Join(dir, "gnu.org/bash", "v5.3.0", "bin")
	_ = os.MkdirAll(binDir, 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "bash"), []byte("x"), 0o755)
	if got := FindClosureBin(closure, dir, "gnu.org/bash", "bash"); got == "" {
		t.Error("expected to find bash")
	}
	if got := FindClosureBin(closure, dir, "gnu.org/bash", "nope"); got != "" {
		t.Errorf("expected empty for missing bin, got %q", got)
	}
	if got := FindClosureBin(closure, dir, "not/in/closure", "x"); got != "" {
		t.Errorf("expected empty for absent project, got %q", got)
	}
}

func TestLoaderName(t *testing.T) {
	switch GOARCH() {
	case "aarch64":
		if LoaderName() != "ld-linux-aarch64.so.1" {
			t.Errorf("LoaderName=%q", LoaderName())
		}
	case "x86-64":
		if LoaderName() != "ld-linux-x86-64.so.2" {
			t.Errorf("LoaderName=%q", LoaderName())
		}
	}
}

func TestFindLoader(t *testing.T) {
	dir := t.TempDir()
	name := map[string]string{"aarch64": "ld-linux-aarch64.so.1", "x86-64": "ld-linux-x86-64.so.2"}[GOARCH()]
	if name == "" {
		t.Skip("unmapped arch")
	}
	ldDir := filepath.Join(dir, "gnu.org/glibc/v2.44.0/lib/glibc-2.44")
	_ = os.MkdirAll(ldDir, 0o755)
	_ = os.WriteFile(filepath.Join(ldDir, name), []byte("x"), 0o755)
	if got := FindLoader(dir); got == "" || filepath.Base(got) != name {
		t.Errorf("FindLoader = %q", got)
	}
	if got := FindLoader(t.TempDir()); got != "" {
		t.Errorf("expected empty for missing loader, got %q", got)
	}
}

func TestPrimaryBin(t *testing.T) {
	// prefer the bin matching the project leaf over first-listed
	if got := PrimaryBin("perl.org", []string{"bin/corelist", "bin/perl"}); got != "perl" {
		t.Errorf("PrimaryBin perl = %q", got)
	}
	// fall back to first when no leaf match
	if got := PrimaryBin("acme.org/tool", []string{"bin/foo", "bin/bar"}); got != "foo" {
		t.Errorf("PrimaryBin fallback = %q", got)
	}
	// no provides -> project leaf
	if got := PrimaryBin("gnu.org/wget", nil); got != "wget" {
		t.Errorf("PrimaryBin no-provides = %q", got)
	}
}

func TestBinNames(t *testing.T) {
	if n := BinNames("gnu.org/wget", []string{"bin/wget", "share/x"}); len(n) != 1 || n[0] != "wget" {
		t.Errorf("BinNames provides = %v", n)
	}
	if n := BinNames("acme.org/tool", nil); len(n) != 1 || n[0] != "tool" {
		t.Errorf("BinNames fallback = %v", n)
	}
}

func TestResolveBinPath(t *testing.T) {
	// On non-windows hosts ResolveBinPath is the identity, regardless of what
	// sits on disk. (The ".exe" preference is exercised on the windows runner.)
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	if got := ResolveBinPath(bin); got != bin {
		t.Errorf("ResolveBinPath = %q, want %q", got, bin)
	}
	// A path that already carries .exe is returned verbatim on every platform.
	if got := ResolveBinPath(bin + ".exe"); got != bin+".exe" {
		t.Errorf("ResolveBinPath(.exe) = %q", got)
	}
}

func TestIsELF(t *testing.T) {
	dir := t.TempDir()
	elfp := filepath.Join(dir, "elf")
	_ = os.WriteFile(elfp, []byte{0x7f, 'E', 'L', 'F', 0, 0}, 0o755)
	scriptp := filepath.Join(dir, "script")
	_ = os.WriteFile(scriptp, []byte("#!/bin/sh\necho hi\n"), 0o755)
	if !IsELF(elfp) {
		t.Error("elf magic not detected")
	}
	if IsELF(scriptp) {
		t.Error("script wrongly detected as ELF")
	}
	if IsELF(filepath.Join(dir, "missing")) {
		t.Error("missing file should be false")
	}
}
