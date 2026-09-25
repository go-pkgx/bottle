package bottle

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// writeDynELF builds a tiny 64-bit little-endian shared object with a .dynamic
// section carrying the given DT_NEEDED names and DT_SONAME. Built by hand
// rather than compiled, so this runs on every lane — including the darwin one,
// where no linker would produce an ELF at all.
func writeDynELF(t *testing.T, path, soname string, needed ...string) {
	t.Helper()
	le := binary.LittleEndian

	// .dynstr: a leading NUL, then each name NUL-terminated.
	strtab := []byte{0}
	off := func(s string) uint64 {
		o := uint64(len(strtab))
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return o
	}
	var dyn []byte
	ent := func(tag elf.DynTag, val uint64) {
		var b [16]byte
		le.PutUint64(b[0:], uint64(tag))
		le.PutUint64(b[8:], val)
		dyn = append(dyn, b[:]...)
	}
	for _, n := range needed {
		ent(elf.DT_NEEDED, off(n))
	}
	if soname != "" {
		ent(elf.DT_SONAME, off(soname))
	}
	// DT_STRTAB/DT_STRSZ are what debug/elf follows to read the names.
	const (
		ehSize  = 64
		shEntSz = 64
		numSec  = 4 // null, .dynstr, .dynamic, .shstrtab
		dynAddr = 0x1000
		strAddr = 0x2000
	)
	shstr := []byte{0}
	nameOff := func(s string) uint32 {
		o := uint32(len(shstr))
		shstr = append(shstr, s...)
		shstr = append(shstr, 0)
		return o
	}
	nDynstr, nDynamic, nShstrtab := nameOff(".dynstr"), nameOff(".dynamic"), nameOff(".shstrtab")

	dynOff := uint64(ehSize)
	strOff := dynOff + uint64(len(dyn))
	shstrOff := strOff + uint64(len(strtab))
	shOff := shstrOff + uint64(len(shstr))

	ent(elf.DT_NULL, 0) // must come last, after the offsets above are fixed
	buf := make([]byte, shOff+numSec*shEntSz)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(buf[16:], uint16(elf.ET_DYN))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], shOff)
	le.PutUint16(buf[52:], ehSize)
	le.PutUint16(buf[58:], shEntSz)
	le.PutUint16(buf[60:], numSec)
	le.PutUint16(buf[62:], 3) // .shstrtab index
	copy(buf[dynOff:], dyn)
	copy(buf[strOff:], strtab)
	copy(buf[shstrOff:], shstr)

	sh := func(i int, name uint32, typ elf.SectionType, addr, off, size, link, entsize uint64) {
		b := buf[shOff+uint64(i)*shEntSz:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], uint32(typ))
		le.PutUint64(b[16:], addr)
		le.PutUint64(b[24:], off)
		le.PutUint64(b[32:], size)
		le.PutUint32(b[40:], uint32(link))
		le.PutUint64(b[56:], entsize)
	}
	sh(1, nDynstr, elf.SHT_STRTAB, strAddr, strOff, uint64(len(strtab)), 0, 0)
	sh(2, nDynamic, elf.SHT_DYNAMIC, dynAddr, dynOff, uint64(len(dyn)), 1, 16)
	sh(3, nShstrtab, elf.SHT_STRTAB, 0, shstrOff, uint64(len(shstr)), 0, 0)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

// What an ELF LOADS is its DT_NEEDED, and not its own DT_SONAME — the name it
// calls itself by is not a dependency, and counting it makes every library
// depend on itself.
func TestELFNeeded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libx.so.1")
	writeDynELF(t, p, "libx.so.1", "libz.so.1", "libc.so.6")
	got, err := ELFNeeded(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "libz.so.1" || got[1] != "libc.so.6" {
		t.Errorf("ELFNeeded = %v", got)
	}
}

// Anything that is not an ELF is not a finding: a store is mostly text.
func TestELFNeededOnSomethingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "readme")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ELFNeeded(p); err == nil {
		t.Error("a text file was read as an ELF")
	}
}

// On linux a DT_NEEDED entry is satisfied by any file of that name anywhere in
// the closure, because the loader searches a path rather than following one.
func TestSonamesUnder(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"a/lib/libz.so.1", "b/lib64/libssl.so.3", "c/lib/pkgconfig/z.pc"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := SonamesUnder([]string{filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "c")})
	if !got["libz.so.1"] || !got["libssl.so.3"] {
		t.Errorf("SonamesUnder = %v", got)
	}
	if got["z.pc"] {
		t.Errorf("a pkg-config file was counted as a library: %v", got)
	}
}

// Two different kinds of outside, and an audit that called either a defect
// would report a hole in every closure on the fleet.
func TestSonameComesFromOutside(t *testing.T) {
	for _, s := range []string{"libc.so.6", "ld-linux-x86-64.so.2", "libstdc++.so.6", "libgomp.so.1", "libcuda.so.1"} {
		if !SonameComesFromOutside(s) {
			t.Errorf("%s is not recognised as coming from outside the closure", s)
		}
	}
	for _, s := range []string{"libz.so.1", "libxml2.so.2", "libssl.so.3"} {
		if SonameComesFromOutside(s) {
			t.Errorf("%s was excused, and it is a closure's own business", s)
		}
	}
}
