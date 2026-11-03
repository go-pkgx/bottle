package bottle

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// A CONCRETE SPEC IS WHAT A BOTTLE IS.
//
// # The question this answers
//
// Two bottles of the same version, compiled with different options, were
// indistinguishable: the identity of a bottle was
//
//	<project> : <version>[_N][-glibc<X>]  ×  <os>/<arch>
//
// and nothing in it names a build option. `openmpi+cuda` and `openmpi~cuda`
// could not coexist — the only way to publish both was the `_N` rebuild
// counter, which is an ORDER ("the newer replaces the older"), not a choice.
// In an HPC pantry that is the difference between expressing a dependency and
// hoping for one.
//
// # Why a hash, and why over everything
//
// Spack is the precedent, including its false starts: it carried THREE hashes
// — dag_hash, build_hash and full_hash — and in 2022 collapsed them into one
// dag_hash covering build, link and run dependencies plus the hash of the
// package file itself. The project that lived this tension longest tried the
// split and came back from it.
//
// So Concrete hashes everything that can change the bytes: the declared
// variants, the resolved closure, and the recipe's own content. Two builds of
// one version differ in their hash the moment anything that produced them
// differs — the Nix property, arrived at from inputs rather than from a naming
// convention somebody has to remember to apply.
//
// # glibc is not a special case
//
// It used to be one: a `-glibc<X>` tag suffix with its own splitter, its own
// branch in selectVersions and its own host-derived selector. It is a
// DEPENDENCY whose version changes the ABI, so it belongs in Deps like any
// other, and the readable suffix was a second spelling of identity — the exact
// shape of defect that let numericKey drop a published version three times
// over (see its comment).
//
// Readability is served by the annotation and the local catalogue, which is
// where `spack find -l` serves it too. The tag carries the address.
type Concrete struct {
	// Variants are the declared build options, as asked for or defaulted.
	Variants Variants
	// Deps is the resolved closure: every project this build was made
	// against, at the exact version and hash it was made against. glibc is
	// one of these.
	Deps []Dep
	// Recipe is the digest of the recipe that produced the build. Without it
	// two builds differ only when their inputs are NAMED differently, and a
	// recipe edit that changes compiler flags would be invisible — which is
	// the original question in its purest form.
	Recipe string
}

// Dep is one resolved edge of a closure: a project at a version, and the hash
// of the concrete spec that version was itself built from.
//
// The hash is part of the edge, not a lookup: depending on "openssl.org 3.6.4"
// is ambiguous once openssl itself has variants, and an identity built from
// the ambiguous half would collide exactly where it matters.
type Dep struct {
	Project string
	Version string
	Hash    string
}

// Variants are declared build options: name to value, booleans spelled "true"
// and "false" so one type carries both `+cuda` and `cuda_arch=80`.
//
// A string value rather than any: the canonical form has to be bytes, and a
// typed union would need a second decision about how each type renders. The
// recipe declares the type and validates; this is the wire.
type Variants map[string]string

// canonSep separates fields inside one canonical line. It is a byte that
// cannot occur in a project name, a version, a variant name or a hash, so the
// canonical form cannot be made ambiguous by its own content — the property
// that makes a hash of it mean anything.
const canonSep = "\x00"

// Canonical renders the spec as the exact bytes that are hashed.
//
// ⛔ EVERY FIELD IS SORTED AND DELIMITED. A canonical form that depended on map
// order would give one build two identities, and one built by concatenation
// without a delimiter would give two builds one: {"ab","c"} and {"a","bc"}
// hash alike the moment the separator is "". Both are tested.
func (c Concrete) Canonical() string {
	var b strings.Builder
	b.WriteString("v1")

	names := make([]string, 0, len(c.Variants))
	for n := range c.Variants {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString(canonSep + "var" + canonSep + n + canonSep + c.Variants[n])
	}

	deps := append([]Dep(nil), c.Deps...)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Project != deps[j].Project {
			return deps[i].Project < deps[j].Project
		}
		if deps[i].Version != deps[j].Version {
			return deps[i].Version < deps[j].Version
		}
		return deps[i].Hash < deps[j].Hash
	})
	for _, d := range deps {
		b.WriteString(canonSep + "dep" + canonSep + d.Project + canonSep + d.Version + canonSep + d.Hash)
	}

	if c.Recipe != "" {
		b.WriteString(canonSep + "recipe" + canonSep + c.Recipe)
	}
	return b.String()
}

// hashLen is how many base32 characters of the digest reach the tag.
//
// 16 characters is 80 bits. An OCI tag is 128 characters at most and must
// match [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}, which excludes base64's "+" and
// "/" and is why this is base32 and not something shorter. Spack spends 32
// characters, conda 7; 16 leaves room for a long version beside it and puts a
// collision far outside the reach of a registry that holds thousands of
// bottles, not quintillions.
const hashLen = 16

// lowerBase32 is RFC 4648 base32 without padding, lowercased: the alphabet an
// OCI tag accepts, and stable across Go versions.
var lowerBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Hash is the spec's address: the first hashLen base32 characters of the
// SHA-256 of its canonical form.
//
// An EMPTY spec hashes to "": a bottle with no declared variants, no recorded
// closure and no recipe digest is one we know nothing about, and giving it an
// address would claim knowledge we do not have. That is also what makes every
// tag published before this existed readable — it has no hash because nothing
// recorded one, which is true.
func (c Concrete) Hash() string {
	if c.IsZero() {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Canonical()))
	return strings.ToLower(lowerBase32.EncodeToString(sum[:]))[:hashLen]
}

// IsZero reports whether nothing about this build was recorded.
func (c Concrete) IsZero() bool {
	return len(c.Variants) == 0 && len(c.Deps) == 0 && c.Recipe == ""
}

// String renders the spec the way a person writes it, which is the way
// `pkgx ls` and the catalogue show it: `+cuda ~mpi cuda_arch=80`.
//
// This is a RENDERING, never an identity. Hash is the identity, and the two
// must not be confused: a reader that compared these strings would call two
// builds equal whenever their deps differ and their variants do not.
func (v Variants) String() string {
	if len(v) == 0 {
		return ""
	}
	names := make([]string, 0, len(v))
	for n := range v {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		switch v[n] {
		case "true":
			out = append(out, "+"+n)
		case "false":
			out = append(out, "~"+n)
		default:
			out = append(out, n+"="+v[n])
		}
	}
	return strings.Join(out, " ")
}

// VariantTag is the suffix a concrete spec contributes to a registry tag, or
// "" when there is nothing to say.
func (c Concrete) VariantTag() string {
	h := c.Hash()
	if h == "" {
		return ""
	}
	return variantSep + h
}

// variantSep introduces the hash in a tag. "-h" rather than "-v" because "v"
// already prefixes versions everywhere in this codebase (the v<version>
// install prefix, the `v` ParseVer strips), and a reader meeting `-v8f3a2c1`
// would reasonably take it for one.
const variantSep = "-h"

// SplitVariantHash cuts a trailing variant hash off a registry tag.
//
//	"3.3.11"                   → "3.3.11", ""
//	"3.3.11-habcdefghij012345" → "3.3.11", "abcdefghij012345"
//
// A suffix that is not exactly hashLen characters of the hash alphabet is NOT
// a hash: `gnu.org/help2man`-style names never reach here, but a version like
// "1.0-h2" would, and reading it as a truncated hash would silently change
// which bottle a pin means.
func SplitVariantHash(tag string) (version, hash string) {
	i := strings.LastIndex(tag, variantSep)
	if i <= 0 {
		return tag, ""
	}
	h := tag[i+len(variantSep):]
	if !isVariantHash(h) {
		return tag, ""
	}
	return tag[:i], h
}

// isVariantHash reports whether s is exactly a variant hash: hashLen
// characters drawn from lowercase base32.
func isVariantHash(s string) bool {
	if len(s) != hashLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// ParseVariants reads the spec spelling of a variant list: "+cuda", "~mpi",
// "cuda_arch=80", separated by spaces.
//
// ⛔ `~` IS ALSO OUR TILDE RANGE OPERATOR, and that collision is the reason
// this parser exists rather than a Split. pkgx spells a version range `~5.44`
// (verDelims is "@^~<>="), while Spack spells a disabled variant `~cuda`.
// They are told apart by what FOLLOWS the tilde: a digit begins a version, a
// letter begins a variant name. `-cuda` is not an option at all — project
// names contain hyphens (llvm.org/mingw-w64), so it cannot be a boundary.
func ParseVariants(s string) (Variants, error) {
	out := Variants{}
	for _, tok := range strings.Fields(s) {
		name, value, err := parseVariant(tok)
		if err != nil {
			return nil, err
		}
		if prev, dup := out[name]; dup && prev != value {
			return nil, fmt.Errorf("variant %q given twice, as %q and %q", name, prev, value)
		}
		out[name] = value
	}
	return out, nil
}

func parseVariant(tok string) (name, value string, err error) {
	switch {
	case strings.HasPrefix(tok, "+"):
		name = tok[1:]
		value = "true"
	case strings.HasPrefix(tok, "~"):
		name = tok[1:]
		value = "false"
		if name != "" && name[0] >= '0' && name[0] <= '9' {
			return "", "", fmt.Errorf("%q is a version range, not a variant: a tilde variant names a variant (~cuda)", tok)
		}
	default:
		n, v, ok := strings.Cut(tok, "=")
		if !ok {
			return "", "", fmt.Errorf("%q is not a variant: write +name, ~name or name=value", tok)
		}
		name, value = n, v
	}
	if name == "" {
		return "", "", fmt.Errorf("%q names no variant", tok)
	}
	if !isVariantName(name) {
		return "", "", fmt.Errorf("%q is not a variant name: letters, digits and underscore, starting with a letter", name)
	}
	return name, value, nil
}

// isVariantName bounds what may reach a canonical form and, through it, a
// hash. Anything outside this cannot appear in a tag, and a name carrying the
// canonical separator could forge another spec's identity.
func isVariantName(s string) bool {
	if s == "" || !isLetter(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isLetter(c) && !(c >= '0' && c <= '9') && c != '_' {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// VariantBool reads a variant as a boolean, reporting whether it was one.
func (v Variants) VariantBool(name string) (val, ok bool) {
	s, present := v[name]
	if !present {
		return false, false
	}
	b, err := strconv.ParseBool(s)
	return b, err == nil
}
