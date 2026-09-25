package bottle

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	lcIDDylib = 0x0d
	lcRpath   = 0x1c | 0x80000000
)

type mcmd struct {
	cmd uint32
	str string
}

// writeMachO builds a Mach-O by hand rather than compiling one, so these tests
// run on every lane. A darwin-only fixture is how the coverage gate on linux
// went short once before.
func writeMachO(t *testing.T, p string, cmds ...mcmd) {
	t.Helper()
	le := binary.LittleEndian
	var body []byte
	for _, c := range cmds {
		strOff := 24
		if c.cmd == lcRpath {
			strOff = 12
		}
		size := strOff + len(c.str) + 1
		for size%8 != 0 {
			size++
		}
		cb := make([]byte, size)
		le.PutUint32(cb[0:], c.cmd)
		le.PutUint32(cb[4:], uint32(size))
		le.PutUint32(cb[8:], uint32(strOff))
		copy(cb[strOff:], c.str)
		body = append(body, cb...)
	}
	buf := make([]byte, 32+len(body))
	le.PutUint32(buf[0:], 0xfeedfacf) // MH_MAGIC_64
	le.PutUint32(buf[4:], 0x0100000c) // CPU_TYPE_ARM64
	le.PutUint32(buf[12:], 6)         // MH_DYLIB
	le.PutUint32(buf[16:], uint32(len(cmds)))
	le.PutUint32(buf[20:], uint32(len(body)))
	copy(buf[32:], body)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// What a file LOADS, and nothing else. LC_ID_DYLIB says where the file expects
// to live: counting it makes every library depend on its own home, and an
// rpath is a search path, not a dependency.
func TestMachoNeededReadsOnlyTheLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libx.dylib")
	writeMachO(t, p,
		mcmd{lcIDDylib, "@rpath/me.org/v1/lib/libx.1.dylib"},
		mcmd{lcLoadDylib, "@rpath/a.org/v1/lib/liba.1.dylib"},
		mcmd{lcLoadWeakDylib, "@rpath/b.org/v2/lib/libb.2.dylib"},
		mcmd{lcReexportDylib, "@rpath/c.org/v3/lib/libc.3.dylib"},
		mcmd{lcRpath, "@loader_path/../.."},
	)
	got, err := MachoNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"@rpath/a.org/v1/lib/liba.1.dylib",
		"@rpath/b.org/v2/lib/libb.2.dylib",
		"@rpath/c.org/v3/lib/libc.3.dylib",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("MachoNeeded = %v, want %v", got, want)
	}
}

// Anything that is not a Mach-O is not a finding: a store is mostly text.
func TestMachoNeededOnSomethingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "readme")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MachoNeeded(p); err == nil {
		t.Error("a text file was read as a Mach-O")
	}
}

// A reference is satisfied when the path it names EXISTS. That is the whole
// darwin test, and it is stricter than ELF's: there is no search.
func TestUnresolvedRefsIsAStatNotASearch(t *testing.T) {
	dir := t.TempDir()
	// The provider that IS there, at the ABI line the consumer asks for.
	writeMachO(t, filepath.Join(dir, "a.org/v1.2.3/lib/liba.1.dylib"))
	if err := os.Symlink("v1.2.3", filepath.Join(dir, "a.org/abi-liba.1.dylib")); err != nil {
		t.Fatal(err)
	}
	writeMachO(t, filepath.Join(dir, "top.org/v9.0/bin/tool"),
		mcmd{lcLoadDylib, "@rpath/a.org/abi-liba.1.dylib/lib/liba.1.dylib"},
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/abi-libxml2.16.dylib/lib/libxml2.16.dylib"},
		mcmd{lcLoadDylib, "/usr/lib/libSystem.B.dylib"},
	)

	got := unresolvedRefs([]string{filepath.Join(dir, "top.org/v9.0")}, dir)
	if len(got) != 1 {
		t.Fatalf("unresolvedRefs = %+v, want only the missing one", got)
	}
	if got[0].project != "gnome.org/libxml2" || got[0].soname != "libxml2.16.dylib" || !got[0].abiLine {
		t.Errorf("got %+v", got[0])
	}
}

// A project name has slashes in it, and the reference comes in two shapes. The
// soname is explicit in one and the filename in the other; both must give the
// same answer, because the repair keys on it.
func TestUnresolvedRefsReadsBothShapes(t *testing.T) {
	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "top.org/v1/bin/tool"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/v2/lib/libxml2.2.dylib"},
		mcmd{lcLoadDylib, "@rpath/gnupg.org/gpgme/abi-libgpgme.11.dylib/lib/libgpgme.11.dylib"},
	)
	got := unresolvedRefs([]string{filepath.Join(dir, "top.org/v1")}, dir)
	if len(got) != 2 {
		t.Fatalf("unresolvedRefs = %+v", got)
	}
	// Sorted by project, so libxml2 comes first.
	if got[0].project != "gnome.org/libxml2" || got[0].soname != "libxml2.2.dylib" || got[0].abiLine {
		t.Errorf("the major-directory shape read as %+v", got[0])
	}
	if got[1].project != "gnupg.org/gpgme" || got[1].soname != "libgpgme.11.dylib" || !got[1].abiLine {
		t.Errorf("the ABI-line shape read as %+v", got[1])
	}
}

// The point of the whole chain: a closure that already holds one ABI line of a
// project installs the OTHER one when something asks for it. This is what a
// resolver keyed on project cannot do, and what hwloc needs in a closure where
// gettext holds libxml2 at 2.13.
func TestCompleteMachOHoldsBothABILines(t *testing.T) {
	old := machoProvider
	defer func() { machoProvider = old }()

	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "gnome.org/libxml2/v2.13.9/lib/libxml2.2.dylib"))
	writeMachO(t, filepath.Join(dir, "open-mpi.org/hwloc/v2.15.0/lib/libhwloc.15.dylib"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/abi-libxml2.16.dylib/lib/libxml2.16.dylib"},
	)
	closure := []Resolved{
		{"gnome.org/libxml2", Ver{Raw: "2.13.9"}},
		{"open-mpi.org/hwloc", Ver{Raw: "2.15.0"}},
	}

	var asked []string
	machoProvider = func(w want, d string) (Resolved, bool) {
		asked = append(asked, w.project+" "+w.soname)
		// Install it, as the real provider would, so the loop converges.
		writeMachO(t, filepath.Join(d, "gnome.org/libxml2/v2.15.4/lib/libxml2.16.dylib"))
		if err := os.Symlink("v2.15.4", filepath.Join(d, "gnome.org/libxml2/abi-libxml2.16.dylib")); err != nil {
			t.Fatal(err)
		}
		return Resolved{"gnome.org/libxml2", Ver{Raw: "2.15.4"}}, true
	}

	got, err := completeMachO(closure, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "gnome.org/libxml2 libxml2.16.dylib" {
		t.Fatalf("asked for %v", asked)
	}
	if len(got) != 3 {
		t.Fatalf("closure = %+v, want the second line added", got)
	}
	// Both lines, one project: the dedup is on project@version.
	var vers []string
	for _, r := range got {
		if r.Project == "gnome.org/libxml2" {
			vers = append(vers, r.Version.Raw)
		}
	}
	if len(vers) != 2 {
		t.Errorf("libxml2 versions in the closure: %v, want both lines", vers)
	}
}

// A reference through v<major> cannot be repaired: one symlink, one owner. Say
// so, naming the rebuild that would fix it — dyld's version of this message
// arrives as a crash with nothing pointing back here.
func TestCompleteMachODiagnosesTheMajorDirectory(t *testing.T) {
	oldW, oldP := Warn, machoProvider
	defer func() { Warn, machoProvider = oldW, oldP }()
	var said []string
	Warn = func(m string) { said = append(said, m) }
	machoProvider = func(want, string) (Resolved, bool) {
		t.Error("a major-directory reference was sent to the provider")
		return Resolved{}, false
	}

	dir := t.TempDir()
	writeMachO(t, filepath.Join(dir, "open-mpi.org/hwloc/v2.15.0/bin/lstopo"),
		mcmd{lcLoadDylib, "@rpath/gnome.org/libxml2/v2/lib/libxml2.16.dylib"},
	)
	if _, err := completeMachO([]Resolved{{"open-mpi.org/hwloc", Ver{Raw: "2.15.0"}}}, dir); err != nil {
		t.Fatal(err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "libxml2.16.dylib") ||
		!strings.Contains(said[0], "major directory") {
		t.Errorf("diagnostics: %v", said)
	}
}

// The provider asks the MANIFEST which version ships the soname, and stops at
// the newest that does — forty small reads instead of forty downloads.
func TestProvideMachoSonameAsksTheManifest(t *testing.T) {
	oldV, oldI, oldA := machoVersions, machoInstall, abiAnnotations
	defer func() { machoVersions, machoInstall, abiAnnotations = oldV, oldI, oldA }()

	machoVersions = func(string) ([]Ver, error) { // ascending, as the real one answers
		return []Ver{{Raw: "2.12.0"}, {Raw: "2.13.9"}, {Raw: "2.15.4"}, {Raw: "2.16.0"}}, nil
	}
	abiAnnotations = func(_, tag, _, _ string) map[string]string {
		switch tag {
		case "2.13.9":
			return map[string]string{ABIProvidesAnnotation: "libxml2.2.dylib"}
		case "2.15.4", "2.16.0":
			return map[string]string{ABIProvidesAnnotation: "libxml2.16.dylib,libxml2mod.dylib"}
		}
		return nil // published before the annotation existed
	}
	var installed []string
	machoInstall = func(r Resolved, _ string) (bool, error) {
		installed = append(installed, r.Version.Raw)
		return true, nil
	}

	r, ok := provideMachoSoname(want{project: "gnome.org/libxml2", soname: "libxml2.16.dylib"}, t.TempDir())
	if !ok || r.Version.Raw != "2.16.0" {
		t.Fatalf("provideMachoSoname = %+v, %v; want the newest that declares it", r, ok)
	}
	if len(installed) != 1 {
		t.Errorf("downloaded %d bottles to answer a manifest question: %v", len(installed), installed)
	}
}

// Nothing declares it: say which reference will not resolve, rather than
// leaving dyld to say it later with no way back to here.
func TestProvideMachoSonameWhenNothingDeclaresIt(t *testing.T) {
	oldV, oldA, oldW := machoVersions, abiAnnotations, Warn
	defer func() { machoVersions, abiAnnotations, Warn = oldV, oldA, oldW }()
	machoVersions = func(string) ([]Ver, error) { return []Ver{{Raw: "1.0"}}, nil }
	abiAnnotations = func(string, string, string, string) map[string]string { return nil }
	var said []string
	Warn = func(m string) { said = append(said, m) }

	if _, ok := provideMachoSoname(want{project: "a.org", soname: "liba.9.dylib", ref: "@rpath/a.org/abi-liba.9.dylib/lib/liba.9.dylib"}, t.TempDir()); ok {
		t.Fatal("claimed to provide a soname nothing declares")
	}
	if len(said) != 1 || !strings.Contains(said[0], "@rpath/a.org/abi-liba.9.dylib") {
		t.Errorf("diagnostics: %v", said)
	}
}

// A lookup that fails is not the same answer as a project whose versions all
// lack the soname: the first is a broken registry, the second is a fact.
func TestProvideMachoSonameWhenTheLookupFails(t *testing.T) {
	oldV, oldW := machoVersions, Warn
	defer func() { machoVersions, Warn = oldV, oldW }()
	machoVersions = func(string) ([]Ver, error) { return nil, errors.New("no such project") }
	var said []string
	Warn = func(m string) { said = append(said, m) }

	if _, ok := provideMachoSoname(want{project: "a.org", soname: "liba.9.dylib"}, t.TempDir()); ok {
		t.Fatal("claimed to provide from a project it could not list")
	}
	if len(said) != 1 || !strings.Contains(said[0], "no such project") {
		t.Errorf("diagnostics: %v", said)
	}
}
