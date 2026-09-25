package bottle

import "debug/elf"

// ELFNeeded is what an ELF file loads: its DT_NEEDED entries.
//
// It is the linux counterpart of MachoNeeded, and the two answer differently
// shaped questions. A Mach-O names a PATH, so "is it satisfied" is a stat. An
// ELF names a SONAME and the loader searches for it, so the question is
// whether ANYTHING in the closure provides that name — which is a comparison
// against the whole store, not against one path.
//
// Both readers live here because an audit that runs on one platform and not
// the other measures half a fleet. This one is exported for `bk unresolved`;
// CompleteClosure has used the same reading to repair a closure for a while.
func ELFNeeded(p string) ([]string, error) {
	f, err := elf.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	return libs, nil
}

// SonamesUnder is every shared-library file name the given installed prefixes
// offer. On linux a DT_NEEDED entry is satisfied by any of them, wherever it
// sits, because the loader searches a path rather than following one.
func SonamesUnder(prefixes []string) map[string]bool {
	return availableSonames(prefixes)
}

// SonameComesFromOutside reports whether a soname is one the CLOSURE is not
// expected to carry.
//
// Two groups, and they are different kinds of outside. The implicit system
// libraries — glibc, the libstdc++/libgcc pair, the gcc runtime — are supplied
// by the installer from their own project groups rather than by the soname
// map, so a closure that has not run that step yet looks short of them without
// being wrong. The host-provided ones are a boundary rather than a gap: a GPU
// driver's userspace half is versioned in lockstep with a kernel module and
// belongs to whoever installed the driver.
//
// An audit that counted either as a defect would report a hole in every
// closure on the fleet.
func SonameComesFromOutside(soname string) bool {
	return isImplicitSoname(soname) || isHostProvidedSoname(soname)
}
