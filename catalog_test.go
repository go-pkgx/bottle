package bottle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
	"time"
)

// A pantry-shaped catalogue: a flat project, a one-level namespace, a
// two-level one, and the case that breaks a naive tree.
func sampleCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-05T09:00:00Z",
		Projects: []CatalogProject{
			{Project: "zlib.net", Versions: []string{"1.3.2"}, Platforms: []string{"linux/x86-64"}},
			{Project: "curl.se", Versions: []string{"8.17.0"}},
			{Project: "curl.se/ca-certs", Versions: []string{"2026.09.25"}},
			{Project: "gnu.org/bash"},
			{Project: "gnu.org/gcc"},
			{Project: "gnu.org/gcc/libstdcxx"},
			{Project: "github.com/besser82/libxcrypt"},
			{Project: "github.com/westes/flex"},
		},
	}
}

// The roots are the first segment of every project, and a project with no
// slash is a root that is itself a leaf.
func TestChildrenAtTheRoot(t *testing.T) {
	c0 := sampleCatalog()
	got := c0.Children("")
	var names []string
	for _, n := range got {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "curl.se github.com gnu.org zlib.net" {
		t.Fatalf("roots = %v", names)
	}
	for _, n := range got {
		switch n.Name {
		case "zlib.net":
			if !n.Leaf || n.Under != 0 {
				t.Errorf("zlib.net should be a pure leaf: %+v", n)
			}
		case "github.com":
			if n.Leaf || n.Under != 2 {
				t.Errorf("github.com should be interior with 2 under it: %+v", n)
			}
		}
	}
}

// THE CASE THAT BREAKS A NAIVE TREE: curl.se is a project AND has
// curl.se/ca-certs under it. Leaf and interior are not exclusive, and a tree
// that made them so would hide one of the two.
func TestANodeThatIsBothAProjectAndAParent(t *testing.T) {
	c0 := sampleCatalog()
	for _, n := range c0.Children("") {
		if n.Name != "curl.se" {
			continue
		}
		if !n.Leaf {
			t.Error("curl.se is a project and the tree does not say so")
		}
		if n.Under != 1 {
			t.Errorf("curl.se has curl.se/ca-certs under it; Under = %d", n.Under)
		}
		return
	}
	t.Fatal("curl.se is not among the roots")
}

// Only ONE segment is expanded. Jumping two levels would skip the choice the
// user is making.
func TestChildrenExpandOneSegmentAtATime(t *testing.T) {
	c := sampleCatalog()
	got := c.Children("github.com")
	var names []string
	for _, n := range got {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "github.com/besser82 github.com/westes" {
		t.Fatalf("github.com children = %v (expected the vendor level, not the projects)", names)
	}
	if got[0].Leaf {
		t.Error("github.com/besser82 is not itself a project and is marked a leaf")
	}
	// And the level below.
	deeper := c.Children("github.com/besser82")
	if len(deeper) != 1 || deeper[0].Name != "github.com/besser82/libxcrypt" || !deeper[0].Leaf {
		t.Errorf("github.com/besser82 children = %+v", deeper)
	}
	// A trailing slash is the same node.
	if len(c.Children("github.com/")) != len(got) {
		t.Error("a trailing slash changed the answer")
	}
}

// A node that does not exist has no children — and says nothing else.
func TestChildrenOfNothing(t *testing.T) {
	c0 := sampleCatalog()
	if got := c0.Children("nope.invalid"); len(got) != 0 {
		t.Errorf("children of an absent node = %+v", got)
	}
	// A prefix that is not a whole segment must not match: `gnu.o` is not
	// `gnu.org`, and a tree that walked into it would invent a node.
	if got := c0.Children("gnu.o"); len(got) != 0 {
		t.Errorf("a partial segment matched a node: %+v", got)
	}
}

// Completion is Children filtered by the partial LAST segment.
func TestComplete(t *testing.T) {
	c := sampleCatalog()
	names := func(ns []Node) string {
		var s []string
		for _, n := range ns {
			s = append(s, n.Name)
		}
		return strings.Join(s, " ")
	}
	if got := names(c.Complete("gnu.org/g")); got != "gnu.org/gcc" {
		t.Errorf("gnu.org/g → %q", got)
	}
	if got := names(c.Complete("gnu.org/")); got != "gnu.org/bash gnu.org/gcc" {
		t.Errorf("gnu.org/ → %q", got)
	}
	if got := names(c.Complete("c")); got != "curl.se" {
		t.Errorf("c → %q", got)
	}
	if got := names(c.Complete("")); got != "curl.se github.com gnu.org zlib.net" {
		t.Errorf("empty → %q", got)
	}
	// gnu.org/gcc is a project AND a parent, so completing it offers it.
	if got := names(c.Complete("gnu.org/gcc")); got != "gnu.org/gcc" {
		t.Errorf("gnu.org/gcc → %q", got)
	}
	if got := names(c.Complete("gnu.org/gcc/")); got != "gnu.org/gcc/libstdcxx" {
		t.Errorf("gnu.org/gcc/ → %q", got)
	}
}

func TestLookup(t *testing.T) {
	c := sampleCatalog()
	p, ok := c.Lookup("zlib.net")
	if !ok || p.Versions[0] != "1.3.2" {
		t.Errorf("Lookup(zlib.net) = %+v %v", p, ok)
	}
	if _, ok := c.Lookup("nope.invalid"); ok {
		t.Error("Lookup invented a project")
	}
}

// Deterministic bytes, because the artefact is signed like a bottle and a
// catalogue whose bytes moved for no reason makes every rebuild look like a
// change.
func TestMarshalIsDeterministicAndSorted(t *testing.T) {
	a := sampleCatalog()
	b := Catalog{Generated: a.Generated}
	for i := len(a.Projects) - 1; i >= 0; i-- { // same set, reversed
		b.Projects = append(b.Projects, a.Projects[i])
	}
	x, err := MarshalCatalog(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := MarshalCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Errorf("the same catalogue in a different order marshals differently:\n%s\n---\n%s", x, y)
	}
	if !strings.HasSuffix(string(x), "\n") {
		t.Error("no trailing newline")
	}
}

// An empty catalogue and an unreadable one must not look alike: the first
// says the registry is empty, the second says we failed to ask.
func TestUnmarshalRefusesWhatIsNotACatalogue(t *testing.T) {
	round, err := MarshalCatalog(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalCatalog(round)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Projects) != len(sampleCatalog().Projects) || back.Generated != "2026-10-05T09:00:00Z" {
		t.Errorf("round trip lost something: %+v", back)
	}
	for _, bad := range []string{"", "not json", "{}", "[]"} {
		if _, err := UnmarshalCatalog([]byte(bad)); err == nil {
			t.Errorf("accepted %q as a catalogue", bad)
		}
	}
	// A catalogue with zero projects but a timestamp IS one: an empty
	// registry is a real answer.
	if _, err := UnmarshalCatalog([]byte(`{"generated":"2026-10-05T09:00:00Z","projects":[]}`)); err != nil {
		t.Errorf("an empty but dated catalogue was refused: %v", err)
	}
}

func TestCatalogAge(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-05T11:30:00Z": "30 minute(s) old",
		"2026-10-05T06:00:00Z": "6 hour(s) old",
		"2026-10-01T12:00:00Z": "4 day(s) old",
		"":                     "of unknown age",
	} {
		if got := (&Catalog{Generated: in}).Age(now); got != want {
			t.Errorf("Age(%q) = %q, want %q", in, got, want)
		}
	}
}

// A real tar, because the manifest says `…layer.tar+gzip` and a reader that
// believes it must not be lied to. This test unpacks it the way `tar tzf`
// would rather than through CatalogFromTarball, so the two cannot agree on a
// shape nothing else can read.
func TestACatalogueLayerIsARealTar(t *testing.T) {
	tgz, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "catalog.json" {
		t.Errorf("the layer holds %q", h.Name)
	}
	body, _ := io.ReadAll(tr)
	if !strings.Contains(string(body), `"zlib.net"`) {
		t.Errorf("the file is not the catalogue:\n%s", body)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Error("the layer holds more than the catalogue")
	}
	// And the bytes are reproducible: same catalogue, same digest.
	again, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tgz, again) {
		t.Error("two packs of the same catalogue differ — the digest would move for nothing")
	}
}

func TestCatalogRoundTripsThroughALayer(t *testing.T) {
	tgz, err := CatalogTarball(sampleCatalog())
	if err != nil {
		t.Fatal(err)
	}
	back, err := CatalogFromTarball(tgz)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Projects) != 8 || back.Generated != "2026-10-05T09:00:00Z" {
		t.Errorf("round trip = %+v", back)
	}
	if n := back.Children("github.com"); len(n) != 2 {
		t.Errorf("the tree did not survive: %+v", n)
	}
}

// Every way a layer can fail to be a catalogue, each said differently.
func TestCatalogFromTarballRefusals(t *testing.T) {
	pack := func(name string, body []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
		_ = tw.Close()
		_ = zw.Close()
		return buf.Bytes()
	}
	for _, c := range []struct {
		name string
		in   []byte
		want string
	}{
		{"not gzip", []byte("plain"), "catalog:"},
		{"no catalog.json", pack("README", []byte("hi")), "holds no catalog.json"},
		{"not a catalogue", pack("catalog.json", []byte("{}")), "not a catalogue"},
		{"broken json", pack("catalog.json", []byte("{")), "catalog:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := CatalogFromTarball(c.in)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v does not say %q", err, c.want)
			}
		})
	}
}

// A catalogue is a list of names. Anything bottle-sized in that slot is not
// one, and reading it because the tar said to is how a reader becomes the
// attack.
func TestCatalogRefusesAnOversizedFile(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	big := bytes.Repeat([]byte("a"), CatalogMaxBytes+1)
	_ = tw.WriteHeader(&tar.Header{Name: CatalogFileName, Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(big)
	_ = tw.Close()
	_ = zw.Close()
	_, err := CatalogFromTarball(buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized catalogue was accepted or misreported: %v", err)
	}
}

// The whole point, end to end against a registry: publish a catalogue for
// one platform, pull it back, and browse the tree that comes out.
//
// Per PLATFORM, and the second half of this test is why: what is available
// differs by architecture, so a catalogue pushed for one must not answer for
// another. The s390x lane having a fraction of linux/x86-64's bottles is the
// case this protects.
func TestPublishAndFetchACatalogue(t *testing.T) {
	t.Setenv("PKGX_VERIFY", "0") // transport round-trip on an unsigned artefact
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/bottles"))
	if err != nil {
		t.Fatal(err)
	}
	osn, arch := HostSlug()

	if err := PublishCatalog(c, sampleCatalog(), osn, arch); err != nil {
		t.Fatal(err)
	}
	got, err := FetchCatalog(c, osn, arch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Projects) != 8 {
		t.Fatalf("fetched %d projects", len(got.Projects))
	}
	// The tree, which is what a browser asks for.
	kids := got.Children("gnu.org")
	var names []string
	for _, n := range kids {
		names = append(names, n.Name)
	}
	if strings.Join(names, " ") != "gnu.org/bash gnu.org/gcc" {
		t.Errorf("gnu.org children after a round trip = %v", names)
	}

	// A platform nothing was published for must FAIL, not return an empty
	// catalogue: "this architecture has nothing" and "I could not ask" are
	// different answers and a browser must not merge them.
	if _, err := FetchCatalog(c, "plan9", "mips64"); err == nil {
		t.Error("a platform with no catalogue returned one")
	}
}

// A catalogue with a dependency DAG: curl needs openssl and zlib, openssl
// needs zlib too (the diamond), and one dependency is not in the catalogue
// at all.
func depCatalog() Catalog {
	return Catalog{
		Generated: "2026-10-05T09:00:00Z",
		Projects: []CatalogProject{
			{Project: "curl.se", Versions: []string{"8.17.0"}, Deps: []string{"openssl.org", "zlib.net", "gone.invalid"}},
			{Project: "openssl.org", Versions: []string{"3.6.4"}, Deps: []string{"zlib.net"}},
			{Project: "zlib.net", Versions: []string{"1.3.2"}},
		},
	}
}

// What is under a PACKAGE node is what it needs — a different question
// from what is under a NAMESPACE node, which is what it contains.
func TestDepTree(t *testing.T) {
	c := depCatalog()
	top := c.DepTree("curl.se", 0)
	var names []string
	for _, n := range top {
		names = append(names, n.Project)
	}
	if strings.Join(names, " ") != "gone.invalid openssl.org zlib.net" {
		t.Fatalf("under curl.se = %v", names)
	}
	for _, n := range top {
		switch n.Project {
		case "openssl.org":
			if n.Version != "3.6.4" || !n.Known {
				t.Errorf("openssl = %+v", n)
			}
			// THE DIAMOND, and which side of it gets expanded. zlib is a
			// direct dependency of curl AND of openssl. The one a reader
			// came for is curl's own, so that is the one shown in full and
			// this nested one is named as a repeat.
			if len(n.Under) != 1 || n.Under[0].Project != "zlib.net" || !n.Under[0].Repeat {
				t.Errorf("under openssl = %+v", n.Under)
			}
		case "zlib.net":
			if n.Repeat {
				t.Error("curl's own direct dependency is shown as a repeat; the nested one was expanded instead")
			}
		case "gone.invalid":
			// A dependency the catalogue does not list must say so, not
			// print like any other node.
			if n.Known {
				t.Error("a dependency with no catalogue entry is marked known")
			}
		}
	}
}

// depth limits the walk, as `guix graph --max-depth` does, because a full
// transitive graph of anything interesting is pages long.
func TestDepTreeDepth(t *testing.T) {
	c := depCatalog()
	one := c.DepTree("curl.se", 1)
	if len(one) != 3 {
		t.Fatalf("depth 1 gave %d nodes", len(one))
	}
	for _, n := range one {
		if len(n.Under) != 0 {
			t.Errorf("depth 1 descended into %s", n.Project)
		}
	}
	// And depth 0 is "no limit", not "nothing".
	if deep := c.DepTree("curl.se", 0); len(deep) != 3 {
		t.Errorf("depth 0 gave %d nodes", len(deep))
	}
}

// A leaf, and a project that is not there at all. Neither is an error and
// they are not the same thing — the caller distinguishes them with Lookup.
func TestDepTreeOfALeafAndOfNothing(t *testing.T) {
	c := depCatalog()
	if got := c.DepTree("zlib.net", 0); len(got) != 0 {
		t.Errorf("zlib has no dependencies; got %+v", got)
	}
	if got := c.DepTree("nope.invalid", 0); len(got) != 0 {
		t.Errorf("an absent project has no subtree; got %+v", got)
	}
}

// A CYCLE must terminate. Recipes have them — the closure walk in bottle
// marks a project seen before descending for exactly this reason — and a
// browser that recursed would hang on the first one.
func TestDepTreeTerminatesOnACycle(t *testing.T) {
	c := Catalog{Projects: []CatalogProject{
		{Project: "a.org", Deps: []string{"b.org"}},
		{Project: "b.org", Deps: []string{"a.org"}},
	}}
	got := c.DepTree("a.org", 0)
	if len(got) != 1 || got[0].Project != "b.org" {
		t.Fatalf("under a.org = %+v", got)
	}
	if len(got[0].Under) != 1 || !got[0].Under[0].Repeat {
		t.Errorf("the cycle back to a.org is not marked as already shown: %+v", got[0].Under)
	}
}

// A CATALOGUE'S VERSIONS REACH THE TERMINAL, and it took a probe to see it:
// `pkgx ls` printed them raw, so a version carrying ESC[2K and a carriage
// return rewrote its own line as a different, reassuring one.
//
//	evil.org   1.0.0^[[2K^Mcurl.se  8.20  ✓ verified by maintainers
//
// Dropped and counted rather than refused: a version string reaches a
// published catalogue from an upstream recipe's `versions:` spec, so
// refusing the whole file would hand any recipe author a switch that turns
// off `pkgx ls`, `search` and every <TAB> for everybody.
func TestACraftedVersionIsDroppedFromACatalogueNotShown(t *testing.T) {
	body := `{"generated":"2026-10-07T00:00:00Z","projects":[` +
		`{"project":"evil.org","versions":["1.0.0\u001b[2K\rcurl.se 8.20 verified","2.0.0"],` +
		`"platforms":["darwin/aarch64"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("the catalogue was refused outright: %v", err)
	}
	p := c.Projects[0]
	for _, v := range p.Versions {
		if strings.ContainsRune(v, 0x1b) {
			t.Errorf("an escape reached a version: %q", v)
		}
	}
	// The GOOD version survives. A guard that threw away the whole list
	// would be a denial of service wearing a fix's clothes.
	if len(p.Versions) != 1 || p.Versions[0] != "2.0.0" {
		t.Errorf("versions = %q, want just the readable one", p.Versions)
	}
	// AND IT IS NOT SILENT. A guard that quietly removes things leaves a
	// reader comparing a short list against their memory.
	if c.Dropped != 1 {
		t.Errorf("Dropped = %d, want 1", c.Dropped)
	}
	// The project stays LISTED, which is the state the type already
	// documents as legal: named by the pantry, nothing this client can
	// fetch.
	if p.Project != "evil.org" {
		t.Errorf("the project was removed with its version: %q", p.Project)
	}
}

// AND A REAL CATALOGUE LOSES NOTHING. The published catalogues of
// 2026-10-06 carry 2801 version strings over fifteen distinct runes; if any
// of them tripped this, `pkgx ls` would start hiding versions that work.
func TestOrdinaryVersionsAreNotDropped(t *testing.T) {
	body := `{"generated":"2026-10-07T00:00:00Z","projects":[` +
		`{"project":"min.io","versions":["2023.10.25.06.33.25","1.3.2","20260526.0","2026.1","1.2.3-rc1"]}]}`
	c, err := UnmarshalCatalog([]byte(body))
	if err != nil {
		t.Fatalf("UnmarshalCatalog: %v", err)
	}
	if c.Dropped != 0 || len(c.Projects[0].Versions) != 5 {
		t.Errorf("dropped %d, kept %q", c.Dropped, c.Projects[0].Versions)
	}
}
