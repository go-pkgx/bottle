package bottle

import (
	"path/filepath"
	"strings"
)

// The store's layout, in one place.
//
// ⛔⛔ A PATH KEYED ON THE VERSION ALONE CANNOT HOLD TWO BUILDS OF ONE VERSION,
// AND THAT IS THE WHOLE PROBLEM THIS FILE EXISTS FOR.
//
// Measured before writing it: the convention `<dir>/<project>/v<version>` was
// spelled out at NINE call sites — install.go:131, 240, 241, 271, 357,
// closure.go:278, 532, pkgx.go:2057, 2155 — and read back at none. Two bottles
// that differ only in their build options resolve to the same directory, so
// installing the second one meets the first and the installer refuses:
//
//	already holds other content … the bottle carries v3.3.11
//
// That refusal is correct behaviour on a wrong layout. `+cuda` and `~cuda`
// are not a sequence, there is no newer one, and nothing in the path says
// which of them is on disk.
//
// So the directory carries the concrete spec's hash when there IS one:
//
//	<dir>/<project>/v3.3.11                      identity not recorded
//	<dir>/<project>/v3.3.11-habcdefghij012345    THIS build of 3.3.11
//
// The bare form is not a default and not a fallback for a hash we could have
// computed. It is the honest statement that a bottle arrived without a spec
// annotation — a mirrored bottle, or one built before bk published one — and
// that nothing on disk can say which build it is. Minting a hash for it would
// put a claim in the path that no witness supports.
//
// ⛔ THE SEPARATOR IS SHARED WITH THE REGISTRY TAG ON PURPOSE. variantSep is
// what `bk` writes into the tag and what SplitVariantHash reads back out, so
// a directory name and a tag suffix cannot drift apart into two spellings of
// one idea. The round trip is asserted, not assumed.

// StorePrefix returns the directory a bottle occupies in a store.
//
// It is the ONLY place that composes one. Nine inline spellings is nine
// chances for one of them to forget the variant hash, and a path that forgets
// it silently addresses somebody else's build.
func StorePrefix(dir, project string, v Ver) string {
	return filepath.Join(dir, project, StoreDirName(v))
}

// StoreDirName is the single directory component under the project.
func StoreDirName(v Ver) string {
	name := "v" + v.Raw
	if v.Variant != "" {
		name += variantSep + v.Variant
	}
	return name
}

// ParseStoreDirName is the other direction: what a directory in the store
// says about the bottle inside it.
//
// It reports false for anything that is not a version directory, which
// includes the `v1` / `v1.2` / `v*` aliases writeVersionLinks leaves beside
// the real ones. A digit after the `v` is what separates a version from a
// word, and the aliases' second character is not one.
//
// ⛔ THE HASH IS CUT BEFORE ParseVer SEES THE NAME. Without that, a variant
// directory parses as a version whose Raw is `3.3.11-habcdefghij012345` — a
// string that matches no constraint, compares below every real 3.3.11, and
// names a release that does not exist. The order here is the correctness.
func ParseStoreDirName(name string) (Ver, bool) {
	if !strings.HasPrefix(name, "v") {
		return Ver{}, false
	}
	body := name[1:]
	if body == "" || body[0] < '0' || body[0] > '9' {
		return Ver{}, false
	}
	raw, hash := SplitVariantHash(body)
	v := ParseVer(raw)
	v.Variant = hash
	return v, true
}
