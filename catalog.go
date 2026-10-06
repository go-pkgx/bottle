package bottle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// A CATALOGUE, because a registry you cannot enumerate cannot be browsed.
//
// # THE MEASUREMENT THAT MADE THIS NECESSARY
//
// An anonymous client can ask ghcr what VERSIONS a project has and cannot ask
// what PROJECTS exist. Measured against ghcr.io/go-pkgx/packages:
//
//	GET /v2/_catalog                               403  (no token issued)
//	GET /v2/go-pkgx/packages/_catalog              403  (no token issued)
//	GET /v2/go-pkgx/packages/zlib.net/tags/list    200  ["1.3.2", …]
//
// The registry API's catalogue endpoint is not served, so `gnu.org/<TAB>`
// has nothing to read. Nix, Guix and Spack all answer this from a LOCAL
// index — a flake/eval cache, a channel checkout, a package repo — and the
// pkgx-native equivalent of a local index is an artefact in the registry
// itself.
//
// # A CATALOGUE IS AN ORDINARY BOTTLE
//
// The same move `members` made for sets: rather than a second kind of
// artefact with its own publishing, signing and mirroring, the catalogue is
// pushed through the path a bottle takes. It is therefore signed, attested,
// cached by the pull-through registry and verified on install by everything
// that already does those things — and a scratch image gets it in ONE pull,
// with no registry API beyond the one it already uses to fetch packages.
type Catalog struct {
	// Generated is RFC3339 UTC. A catalogue is a snapshot and says so: a
	// reader deciding whether to refresh wants the age, and a reader
	// reporting "no such project" should be able to say how old its answer
	// is rather than implying the registry was asked just now.
	Generated string           `json:"generated"`
	Projects  []CatalogProject `json:"projects"`
}

// CatalogProject is one project as the catalogue knows it.
type CatalogProject struct {
	Project string `json:"project"`
	// Versions newest-first, as a reader wants them. Empty is legal and
	// means "named by the pantry, nothing published" — which is the honest
	// answer for most of a pantry on most architectures, and is different
	// from the project not existing.
	Versions []string `json:"versions,omitempty"`
	// Platforms as `os/arch`, sorted. Also legal empty, for the same reason.
	Platforms []string `json:"platforms,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	// Deps are the project's declared RUNTIME dependencies, reduced for the
	// platform this catalogue is for, sorted.
	//
	// They are here so the dependency tree can be walked with NO NETWORK
	// and no pantry: `pkgx --graph` answers the same question by resolving
	// against the registry, which a scratch image cannot do before it has
	// one, and which nobody can do on a train.
	//
	// RUNTIME only, deliberately. A build dependency is paid once by the
	// factory and is not in anybody's installed closure; showing it under a
	// node would answer a question the person browsing did not ask.
	Deps []string `json:"deps,omitempty"`
	// Provides are the COMMAND names this project puts on PATH, without
	// their `bin/` prefix, sorted.
	//
	// Here because it is the only metadata in this pantry a search can
	// work on. Measured on 1907 recipes: 1592 declare `provides` and
	// SIX carry a summary. `nix search` and `guix search` look in the
	// description, which is the right design for a collection that has
	// descriptions; here it would find almost nothing.
	//
	// And it answers the question people actually arrive with. You know
	// the command, not the package: `rg` is `crates.io/ripgrep`, which no
	// amount of guessing at the name reaches.
	Provides []string `json:"provides,omitempty"`
}

// CatalogProject implements the one thing a tree browser needs beyond the
// list: what sits under a node.

// Node is one entry under a tree node, as `pkgx ls` and tab-completion show
// it.
type Node struct {
	// Name is the FULL project path of a leaf, or the path of the interior
	// node including its trailing segment — never a bare segment, so a
	// caller can complete straight onto it without reassembling anything.
	Name string
	// Leaf is true when Name is itself a published project.
	//
	// Leaf and Interior are NOT exclusive, and that is not a corner case:
	// `curl.se` is a project and `curl.se/ca-certs` lives under it. A tree
	// that made them exclusive would hide one of the two.
	Leaf bool
	// Under is how many projects sit strictly below Name. Zero for a pure
	// leaf.
	Under int
}

// Children returns what is available directly under a node, sorted.
//
// prefix is "" for the roots, or a node path with or without a trailing
// slash. Only the NEXT path segment is expanded: `github.com` yields
// `github.com/besser82`, not `github.com/besser82/libxcrypt`, because a
// completion that jumped two levels would skip the choice the user is making.
func (c *Catalog) Children(prefix string) []Node {
	prefix = strings.TrimSuffix(prefix, "/")
	want := ""
	if prefix != "" {
		want = prefix + "/"
	}
	byName := map[string]*Node{}
	for _, p := range c.Projects {
		if want != "" && !strings.HasPrefix(p.Project, want) {
			continue
		}
		rest := strings.TrimPrefix(p.Project, want)
		if rest == "" {
			// The node itself is a project. Not a child of itself.
			continue
		}
		seg, deeper, _ := strings.Cut(rest, "/")
		full := want + seg
		n := byName[full]
		if n == nil {
			n = &Node{Name: full}
			byName[full] = n
		}
		if deeper == "" {
			n.Leaf = true
		} else {
			n.Under++
		}
	}
	out := make([]Node, 0, len(byName))
	for _, n := range byName {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns one project's entry, and whether the catalogue has it.
func (c *Catalog) Lookup(project string) (CatalogProject, bool) {
	for _, p := range c.Projects {
		if p.Project == project {
			return p, true
		}
	}
	return CatalogProject{}, false
}

// Complete returns the completions for a partially typed project name.
//
// It is Children of the enclosing node, filtered by the partial segment. A
// node with exactly one child still returns that one rather than jumping to
// its grandchild: a shell completes to the common prefix and the user decides
// whether to descend.
func (c *Catalog) Complete(partial string) []Node {
	node, seg := "", partial
	if i := strings.LastIndex(partial, "/"); i >= 0 {
		node, seg = partial[:i], partial[i+1:]
	}
	var out []Node
	for _, n := range c.Children(node) {
		last := n.Name
		if i := strings.LastIndex(last, "/"); i >= 0 {
			last = last[i+1:]
		}
		if strings.HasPrefix(last, seg) {
			out = append(out, n)
		}
	}
	return out
}

// DepTree is the dependency subtree under a project, as a browser shows it.
//
// # WHY A SEPARATE SHAPE FROM Children
//
// A node has two kinds of thing under it and they are not the same
// question. `gnu.org` has `gnu.org/bash` under it because of how it is
// NAMED; `curl.se` has `openssl.org` under it because of what it NEEDS.
// Nix, Guix and Spack keep the two apart as well — `guix graph` and
// `nix-tree` walk the dependency graph, and neither is how you find out
// what a channel contains.
//
// depth 0 means "no limit". `guix graph --max-depth` exists because a full
// transitive graph of anything interesting is pages long, and the first
// level is what a person reads.
func (c *Catalog) DepTree(project string, depth int) []DepNode {
	index := map[string]CatalogProject{}
	for _, p := range c.Projects {
		index[p.Project] = p
	}
	seen := map[string]bool{project: true}
	var walk func(string, int) []DepNode
	walk = func(p string, level int) []DepNode {
		if depth > 0 && level >= depth {
			return nil
		}
		kids := append([]string(nil), index[p].Deps...)
		sort.Strings(kids)

		// THE WHOLE LEVEL IS MARKED BEFORE ANY OF IT IS DESCENDED INTO.
		//
		// A DAG, not a tree: a project reached twice is named again and not
		// expanded a second time, or a diamond turns a readable tree into
		// pages of the same subtree — `pkgx --graph` says the same in its
		// own comment.
		//
		// Marking level-by-level rather than as the walk goes decides WHICH
		// of the two occurrences gets expanded, and the first version of
		// this got it backwards: curl declares openssl and zlib, openssl
		// declares zlib, and a depth-first mark expanded zlib UNDER OPENSSL
		// and showed curl's own direct dependency as a repeat. A project's
		// direct dependencies are the ones a reader came for.
		var fresh []string
		for _, d := range kids {
			if !seen[d] {
				seen[d] = true
				fresh = append(fresh, d)
			}
		}
		isFresh := map[string]bool{}
		for _, d := range fresh {
			isFresh[d] = true
		}

		out := make([]DepNode, 0, len(kids))
		for _, d := range kids {
			n := DepNode{Project: d}
			if e, ok := index[d]; ok {
				n.Known = true
				if len(e.Versions) > 0 {
					n.Version = e.Versions[0]
				}
			}
			if isFresh[d] {
				n.Under = walk(d, level+1)
			} else {
				n.Repeat = true
			}
			out = append(out, n)
		}
		return out
	}
	return walk(project, 0)
}

// DepNode is one dependency, and what hangs under it.
type DepNode struct {
	Project string
	Version string
	// Known is false for a dependency the catalogue does not list. It
	// happens, and saying so is the point: a name with nothing behind it is
	// a hole in the catalogue or a project that resolves from somewhere
	// else, and a browser that printed it like any other node would hide
	// both.
	Known  bool
	Repeat bool // already shown higher up; not descended into
	Under  []DepNode
}

// Age is how old the catalogue is, in words. A browser that cannot reach the
// registry should still say what it is showing rather than imply it is now.
func (c *Catalog) Age(now time.Time) string {
	t, err := time.Parse(time.RFC3339, c.Generated)
	if err != nil {
		return "of unknown age"
	}
	d := now.UTC().Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s) old", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s) old", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s) old", int(d.Hours()/24))
}

// MarshalCatalog renders a catalogue deterministically: projects sorted,
// versions and platforms sorted within each.
//
// Deterministic because the artefact is signed and attested like a bottle,
// and a catalogue whose bytes moved for no reason would make every rebuild
// look like a change — the same argument the lock makes for sorting its pins.
func MarshalCatalog(c Catalog) ([]byte, error) {
	out := Catalog{Generated: c.Generated, Projects: append([]CatalogProject(nil), c.Projects...)}
	sort.Slice(out.Projects, func(i, j int) bool { return out.Projects[i].Project < out.Projects[j].Project })
	for i := range out.Projects {
		sort.Strings(out.Projects[i].Platforms)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		// Unreachable: every field is a string or a slice of strings.
		return nil, err
	}
	return append(b, '\n'), nil
}

// UnmarshalCatalog is the other direction, refusing a document that is not
// one rather than returning an empty catalogue.
//
// An empty catalogue and an unreadable one must not look alike: the first
// says the registry is empty, the second says we failed to ask, and a
// browser that confused them would tell a user their package does not exist.
func UnmarshalCatalog(b []byte) (Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return Catalog{}, fmt.Errorf("catalog: %w", err)
	}
	if c.Generated == "" && c.Projects == nil {
		return Catalog{}, fmt.Errorf("catalog: no `generated` and no `projects` — this is not a catalogue")
	}
	return c, nil
}

// CatalogProjectName is the reserved project the catalogue is published
// under. A project name rather than a special path, because that is what
// makes it an ordinary bottle.
const CatalogProjectName = "go-pkgx.dev/catalog"

// CatalogVersion is the version it is published as. One moving tag rather
// than a dated series: a catalogue is a cache of the registry, every reader
// wants the newest, and a hundred dated versions of it would be a hundred
// things to garbage-collect.
const CatalogVersion = "1"

// CatalogTarball packs a catalogue into the shape a bottle layer has: a
// gzipped tar holding one file, `catalog.json`.
//
// A real tar, not gzipped JSON wearing a tar media type. The manifest says
// `…layer.tar+gzip` and a reader that believes it — `tar tzf`, or any tool
// that unpacks a bottle — must not be lied to for the sake of fifteen lines.
func CatalogTarball(c Catalog) ([]byte, error) {
	body, err := MarshalCatalog(c)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	// A fixed mode and a zero mtime, so the same catalogue gives the same
	// bytes and therefore the same digest. The push path already pins the
	// manifest's created-time for this reason.
	if err := tw.WriteHeader(&tar.Header{
		Name: CatalogFileName, Mode: 0o644, Size: int64(len(body)),
		Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC(),
	}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(body); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CatalogFromTarball is the other direction.
func CatalogFromTarball(b []byte) (Catalog, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return Catalog{}, fmt.Errorf("catalog: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Catalog{}, fmt.Errorf("catalog: %w", err)
		}
		if h.Name != CatalogFileName {
			continue
		}
		// Bounded. A catalogue is a list of names; anything the size of a
		// bottle in this slot is not one, and reading it into memory because
		// the tar said to is how a reader becomes the attack.
		body, err := io.ReadAll(io.LimitReader(tr, CatalogMaxBytes+1))
		if err != nil {
			return Catalog{}, fmt.Errorf("catalog: %w", err)
		}
		if len(body) > CatalogMaxBytes {
			return Catalog{}, fmt.Errorf("catalog: %s is larger than %d bytes", CatalogFileName, CatalogMaxBytes)
		}
		return UnmarshalCatalog(body)
	}
	return Catalog{}, fmt.Errorf("catalog: the archive holds no %s", CatalogFileName)
}

const (
	// CatalogFileName is the one file a catalogue layer holds.
	CatalogFileName = "catalog.json"
	// CatalogMaxBytes bounds what a reader will take from that file. The
	// whole pkgx pantry is ~1900 projects; 32 MiB is two orders of magnitude
	// of headroom and still refuses a bottle-sized surprise.
	CatalogMaxBytes = 32 << 20
)

// PublishCatalog pushes a catalogue for ONE platform, through the path a
// bottle takes.
//
// Per platform, and that is not an accident of the signature. What is
// available differs by architecture — the s390x lane has a fraction of what
// linux/x86-64 has — so a single catalogue would tell most readers that
// packages are available which, for them, are not. `bk weather` exists
// because that asymmetry is real.
func PublishCatalog(c *OCIClient, cat Catalog, osn, arch string) error {
	tgz, err := CatalogTarball(cat)
	if err != nil {
		return err
	}
	return c.Push(CatalogProjectName, CatalogVersion, osn, arch, tgz, ExtTarGz)
}

// FetchCatalog pulls the catalogue for one platform, and VERIFIES it.
//
// # WHY A LIST OF NAMES NEEDS A SIGNATURE
//
// This was the one path that brought bottle bytes onto a machine without
// the fail-closed check every other bottle gets — which is precisely what
// the comment above verifyPulled promised could not happen. It was missed
// because a catalogue "is only a list of names", and that is the wrong way
// round: a list of names is what a person then TYPES.
//
// Someone able to serve a forged catalogue — a compromised mirror, or a
// PKGX_DIST pointed somewhere by a script — cannot make the install path
// accept an unsigned bottle, because that path still verifies. What they
// can do is decide what `<TAB>` offers, and a near-miss name offered at the
// prompt is the whole of a typosquat. The attack is on the reader, not on
// the installer, and the signature is the only thing that answers it.
//
// It also matters MORE than for an ordinary bottle now, not less: since
// the catalogue became a file on disk, it is fetched once and then read by
// every completion for days. A bottle is verified each time it is pulled;
// this one is verified once and trusted thereafter.
func FetchCatalog(c *OCIClient, osn, arch string) (Catalog, error) {
	b, _, err := c.Pull(CatalogProjectName, CatalogVersion, osn, arch)
	if err != nil {
		return Catalog{}, err
	}
	if err := verifyPulled(c, CatalogProjectName, CatalogVersion, osn, arch, b); err != nil {
		return Catalog{}, err
	}
	return CatalogFromTarball(b)
}
