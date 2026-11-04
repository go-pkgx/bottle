package bottle

import (
	"fmt"
	"sort"
	"strings"
)

// Listing the builds of a version, and naming one.
//
// ⛔⛔ THE RESOLVER REFUSES AN AMBIGUOUS VERSION, AND UNTIL NOW THAT WAS A
// DEAD END. It says, correctly:
//
//	fftw.org 3.3.11 was published as 2 different builds (…) and nothing here
//	says which: a variant hash is not a version, so there is no newest one
//	to pick
//
// A refusal that cannot be answered is only half a design. These are the two
// halves it was missing: ask WHICH builds exist, and say which one you mean.

// Build is one build of one version: what distinguishes it, and where it is.
type Build struct {
	Version Ver
	// Installed is its path in the store, or "" when it is only published.
	Installed string
	// Published says the registry carries it.
	Published bool
}

// Hash is the build's address — the short form that appears in its tag and
// its directory name.
func (b Build) Hash() string { return b.Version.Variant }

// BuildsOf lists every build of one version of a project: those installed in
// dir, those published for osn/arch, and the ones that are both.
//
// ⛔ ONE ANSWER FOR TWO SOURCES, BECAUSE A USER ASKING "WHICH BUILDS ARE
// THERE" DOES NOT MEAN ONE OF THEM. A list of only the installed ones cannot
// answer "what else could I have"; a list of only the published ones cannot
// answer "what do I already have". Reporting them separately would make the
// caller join two lists by hash, which is this function.
//
// ⛔ A REGISTRY THAT COULD NOT BE REACHED IS AN ERROR, NOT AN EMPTY LIST. An
// unobtained answer must not read as "nothing is published" — that is how a
// user concludes a build does not exist and rebuilds it. The installed half
// is still returned alongside the error, because it is a true answer to half
// the question and it needs no network.
func BuildsOf(project, version, dir, osn, arch string) ([]Build, error) {
	byHash := map[string]*Build{}
	var order []string

	for _, v := range InstalledBuilds(project, dir) {
		if v.Raw != version {
			continue
		}
		b := &Build{Version: v, Installed: StoreBuildPrefix(dir, project, v, v.Variant)}
		byHash[v.Variant] = b
		order = append(order, v.Variant)
	}

	published, err := publishedBuildsOf(project, version, osn, arch)
	if err != nil {
		return collect(byHash, order), err
	}
	for _, v := range published {
		if b, ok := byHash[v.Variant]; ok {
			b.Published = true
			continue
		}
		byHash[v.Variant] = &Build{Version: v, Published: true}
		order = append(order, v.Variant)
	}
	return collect(byHash, order), nil
}

// publishedBuildsOf is the registry half, kept separate so the store half
// works with no network at all.
func publishedBuildsOf(project, version, osn, arch string) ([]Ver, error) {
	vers, err := VersionsFor(project, osn, arch)
	if err != nil {
		return nil, err
	}
	var out []Ver
	for _, v := range vers {
		if v.Raw == version {
			out = append(out, v)
		}
	}
	return out, nil
}

// collect renders the map in a stable order: by hash, because builds of one
// version are SIBLINGS.
//
// ⛔ NOT "NEWEST FIRST". There is no newest: two builds of one version differ
// in their options, not in time, and cmpVer ignores the hash for exactly that
// reason. Sorting by hash is arbitrary and says so; sorting by anything that
// looked like precedence would invent one.
func collect(byHash map[string]*Build, order []string) []Build {
	sort.Strings(order)
	out := make([]Build, 0, len(order))
	seen := map[string]bool{}
	for _, h := range order {
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, *byHash[h])
	}
	return out
}

// ParseBuildRef splits a spec that may name a build by hash.
//
//	fftw.org                  → "fftw.org", ""
//	fftw.org@3.3.11           → "fftw.org@3.3.11", ""
//	fftw.org@3.3.11/7k2mq4xv  → "fftw.org@3.3.11", "7k2mq4xv"
//
// ⛔ `/<hash>` IS SPACK'S SPELLING AND IT IS BORROWED ON PURPOSE. Its manual:
// "In place of a spec in any command, substitute /<hash> where <hash> is any
// amount from the beginning of a spec hash." It is the one form that works
// without knowing a package's variant vocabulary, which matters most exactly
// when a user has just been handed two hashes by a refusal and has to pick.
//
// ⛔⛔ THE `@version` IS REQUIRED BEFORE THE HASH, AND THAT IS THE WHOLE RULE.
// A project name contains slashes — a third of the pantry is named that way
// — so a trailing component cannot be told from a hash by LOOKING at it.
//
// The first attempt tried: split on the last slash when the tail "looks like
// a hash", justified by the claim that a pantry component would contain a
// letter outside base32's alphabet or be longer than a hash. That claim is
// FALSE, and a test refuted it immediately: base32 is a–z plus 2–7, which
// covers very nearly every lowercase word. `x.org/pciaccess`,
// `gnome.org/libxml2`, `wpewebkit.org/libwpe` and `github.com/gabime/spdlog`
// all parsed as hash references.
//
// So the syntax decides, not the shape: a hash may only follow an `@version`,
// and without one a trailing component is part of the project name. Always,
// with no exception to get wrong.
func ParseBuildRef(spec string) (rest, hash string) {
	i := strings.LastIndexByte(spec, '/')
	if i < 0 {
		return spec, ""
	}
	// No version, no hash: `x.org/pciaccess` is a project, full stop.
	if !strings.Contains(spec[:i], "@") {
		return spec, ""
	}
	h := spec[i+1:]
	if !isPartialHash(h) {
		return spec, ""
	}
	return spec[:i], h
}

// isPartialHash reports whether s could be the start of a build hash: at
// least four characters, all from the hash alphabet, and no longer than a
// whole one.
//
// ⛔ THIS IS A SANITY CHECK, NOT THE DISAMBIGUATION. ParseBuildRef already
// knows a hash is a hash because an `@version` precedes it; this only
// catches a typo early — `fftw.org@3.3.11/not-a-hash` says so here rather
// than failing later as "no build matches".
func isPartialHash(s string) bool {
	if len(s) < 4 || len(s) > hashLen {
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

// MatchBuild finds the one build whose hash starts with prefix.
//
// ⛔ EXACTLY ONE, OR AN ERROR NAMING THE CANDIDATES. A prefix that matches
// two builds is a question, not a choice, and answering it by picking the
// first would give a different answer as soon as another build is published.
// The error lists them so the next attempt can be longer.
func MatchBuild(builds []Build, prefix string) (Build, error) {
	var hit []Build
	for _, b := range builds {
		if strings.HasPrefix(b.Hash(), prefix) {
			hit = append(hit, b)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return Build{}, fmt.Errorf("no build here has a hash starting %q (have: %s)", prefix, hashList(builds))
	default:
		return Build{}, fmt.Errorf("%q matches %d builds (%s): say more of the hash", prefix, len(hit), hashList(hit))
	}
}

func hashList(builds []Build) string {
	if len(builds) == 0 {
		return "none"
	}
	hs := make([]string, 0, len(builds))
	for _, b := range builds {
		hs = append(hs, b.Hash())
	}
	return strings.Join(hs, ", ")
}
