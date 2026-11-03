package bottle

import (
	"strings"
	"testing"
)

// ⛔⛔ THE QUESTION THIS TYPE EXISTS FOR: two builds of ONE version that differ
// only in a build option must not share an identity. Before Concrete they
// shared a tag, and the only way to publish both was the `_N` counter, which
// is an order and not a choice.
func TestTwoVariantsOfOneVersionHaveDifferentHashes(t *testing.T) {
	with := Concrete{Variants: Variants{"cuda": "true"}}
	without := Concrete{Variants: Variants{"cuda": "false"}}
	if with.Hash() == without.Hash() {
		t.Fatalf("+cuda and ~cuda share the hash %q", with.Hash())
	}
	if with.Hash() == "" || without.Hash() == "" {
		t.Error("a declared variant must produce a hash")
	}
}

// The same spec hashes alike however its maps and slices were built: a hash
// that depended on map iteration order would give ONE build two identities,
// and the registry would hold the same bottle twice under different names.
func TestTheHashDoesNotDependOnOrder(t *testing.T) {
	a := Concrete{
		Variants: Variants{"cuda": "true", "mpi": "false", "arch": "80"},
		Deps: []Dep{
			{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "aaaa"},
			{Project: "openssl.org", Version: "3.5.8", Hash: "bbbb"},
		},
	}
	b := Concrete{
		Variants: Variants{"arch": "80", "mpi": "false", "cuda": "true"},
		Deps: []Dep{
			{Project: "openssl.org", Version: "3.5.8", Hash: "bbbb"},
			{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "aaaa"},
		},
	}
	if a.Hash() != b.Hash() {
		t.Errorf("one spec, two hashes:\n  %q\n  %q", a.Canonical(), b.Canonical())
	}
}

// ⛔ AND THE DELIMITER IS LOad-BEARING. Concatenation without one lets two
// different specs produce identical bytes — {"ab","c"} against {"a","bc"} —
// which is a hash collision manufactured by the encoding rather than found.
func TestTheCanonicalFormCannotBeForgedByConcatenation(t *testing.T) {
	a := Concrete{Variants: Variants{"ab": "c"}}
	b := Concrete{Variants: Variants{"a": "bc"}}
	if a.Canonical() == b.Canonical() {
		t.Errorf("two specs share a canonical form: %q", a.Canonical())
	}
	if a.Hash() == b.Hash() {
		t.Error("two specs share a hash")
	}
}

// ⛔⛔ glibc IS A DEPENDENCY, NOT A SPECIAL CASE. It used to be a `-glibc<X>`
// tag suffix with its own splitter and its own branch in selectVersions — a
// second spelling of identity, which is the shape of defect that let
// numericKey drop a published version three times over.
func TestAGlibcDifferenceIsJustADependencyDifference(t *testing.T) {
	old := Concrete{Deps: []Dep{{Project: "gnu.org/glibc", Version: "2.27.0", Hash: "x"}}}
	new_ := Concrete{Deps: []Dep{{Project: "gnu.org/glibc", Version: "2.44.0", Hash: "y"}}}
	if old.Hash() == new_.Hash() {
		t.Error("two glibc builds share a hash")
	}
}

// ⛔ THE RECIPE'S OWN CONTENT IS IN THE HASH, which is what makes this answer
// the original question without anybody declaring a variant: a recipe edit
// that changes compiler flags produces different bytes, so it must produce a
// different identity. This is the Nix property — identity from inputs, not
// from a naming convention someone has to remember.
func TestARecipeEditChangesTheIdentity(t *testing.T) {
	before := Concrete{Recipe: "sha256:aaa"}
	after := Concrete{Recipe: "sha256:bbb"}
	if before.Hash() == after.Hash() {
		t.Error("two recipes share a hash")
	}
}

// A spec that records nothing has no address, and that is the honest answer:
// every tag published before this existed carries no hash because nothing
// recorded one.
func TestAnEmptySpecHasNoHash(t *testing.T) {
	if got := (Concrete{}).Hash(); got != "" {
		t.Errorf("Hash() = %q, want empty", got)
	}
	if got := (Concrete{}).VariantTag(); got != "" {
		t.Errorf("VariantTag() = %q, want empty", got)
	}
}

// The hash has to survive a tag: OCI allows [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}
// and nothing else, which is why this is base32 and not base64.
func TestTheHashFitsAnOCITag(t *testing.T) {
	h := Concrete{Variants: Variants{"cuda": "true"}}.Hash()
	if len(h) != hashLen {
		t.Errorf("hash %q is %d characters, want %d", h, len(h), hashLen)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			t.Errorf("hash %q holds %q, which an OCI tag refuses", h, c)
		}
	}
}

func TestVariantTagRoundTrips(t *testing.T) {
	c := Concrete{Variants: Variants{"cuda": "true"}}
	tag := "3.3.11" + c.VariantTag()
	ver, hash := SplitVariantHash(tag)
	if ver != "3.3.11" || hash != c.Hash() {
		t.Errorf("SplitVariantHash(%q) = %q, %q; want %q, %q", tag, ver, hash, "3.3.11", c.Hash())
	}
}

// ⛔ A SUFFIX THAT MERELY LOOKS LIKE A HASH IS NOT ONE. Reading "1.0-h2" as a
// truncated hash would silently change which bottle a pin means, and a
// version is free to end in anything.
func TestOnlyAnExactHashIsReadAsOne(t *testing.T) {
	for _, tag := range []string{"3.3.11", "1.0-h2", "1.0-hABCDEFGHIJ012345", "1.0-h" + strings.Repeat("a", hashLen+1), "-habcdefghij012345"} {
		if _, h := SplitVariantHash(tag); h != "" {
			t.Errorf("SplitVariantHash(%q) read %q as a hash", tag, h)
		}
	}
}

// ⛔⛔ `~` IS OUR TILDE RANGE OPERATOR TOO. pkgx spells a version range ~5.44
// and Spack spells a disabled variant ~cuda; the digit after the tilde is
// what tells them apart, and getting it wrong turns a range into a variant
// named "5.44" that nothing declares.
func TestATildeRangeIsNotAVariant(t *testing.T) {
	if _, err := ParseVariants("~5.44"); err == nil {
		t.Error("~5.44 parsed as a variant")
	}
	v, err := ParseVariants("~cuda")
	if err != nil {
		t.Fatalf("~cuda: %v", err)
	}
	if got, ok := v.VariantBool("cuda"); ok && got {
		t.Error("~cuda is cuda=false")
	}
}

func TestParseVariantsSpellings(t *testing.T) {
	v, err := ParseVariants("+cuda ~mpi cuda_arch=80")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"cuda": "true", "mpi": "false", "cuda_arch": "80"} {
		if v[name] != want {
			t.Errorf("%s = %q, want %q", name, v[name], want)
		}
	}
	// And it renders back the way a person writes it.
	if got := v.String(); got != "+cuda cuda_arch=80 ~mpi" {
		t.Errorf("String() = %q", got)
	}
}

// ⛔ A NAME CARRYING THE CANONICAL SEPARATOR COULD FORGE ANOTHER SPEC'S
// IDENTITY, so the parser bounds what can ever reach the canonical form.
func TestAVariantNameIsBounded(t *testing.T) {
	for _, bad := range []string{"+cu\x00da", "+cu da", "+1cuda", "+", "~", "cuda", "+cu-da", "=80"} {
		if _, err := ParseVariants(bad); err == nil {
			t.Errorf("ParseVariants(%q) was accepted", bad)
		}
	}
}

func TestTheSameVariantTwiceDisagreeing(t *testing.T) {
	if _, err := ParseVariants("+cuda ~cuda"); err == nil {
		t.Error("+cuda ~cuda was accepted")
	}
	// Saying the same thing twice is not a conflict.
	if _, err := ParseVariants("+cuda +cuda"); err != nil {
		t.Errorf("+cuda +cuda: %v", err)
	}
}
