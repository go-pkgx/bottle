package bottle

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
)

// The store is addressed by CONTENT: the sha256 the fetcher already computed
// becomes the tag, so the digest a bottle's SBOM records IS the address of the
// bytes it was built from. Nothing has to be named twice or kept in step.
func TestSourceRoundTrip(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("a source tarball, byte for byte as it arrived")
	dg := SourceDigest(data)

	if have, err := c.HasSource("acme.org/thing", dg); err != nil || have {
		t.Fatalf("HasSource before push = %v, %v; want false, nil", have, err)
	}
	if _, err := c.PushSource("acme.org/thing", data, "https://example.invalid/thing-1.2.3.tar.gz"); err != nil {
		t.Fatal(err)
	}
	if have, err := c.HasSource("acme.org/thing", dg); err != nil || !have {
		t.Fatalf("HasSource after push = %v, %v; want true, nil", have, err)
	}
	got, err := c.PullSource("acme.org/thing", dg)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("pulled %q, want %q", got, data)
	}
}

// Pushing the same bytes twice is the same manifest under the same tag, because
// the tag IS the content. A populate step that runs on every build must not
// grow the registry once per build.
func TestSourcePushIsIdempotent(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("same bytes twice")
	first, err := c.PushSource("acme.org/thing", data, "https://example.invalid/a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.PushSource("acme.org/thing", data, "https://example.invalid/a")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Errorf("manifest digests differ: %s vs %s", first.Digest, second.Digest)
	}
}

// A digest the store does not hold is a NAMED absence, not a generic error: the
// caller's next move is to fetch from upstream, and it has to be able to tell
// that case from a broken registry.
func TestPullSourceAbsentIsNamed(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", SourceDigest([]byte("never stored")))
	if !errors.Is(err, ErrSourceAbsent) {
		t.Errorf("err = %v, want ErrSourceAbsent", err)
	}
}

// A mirror exists so a rebuild need not trust the upstream host. Trusting the
// mirror instead would move the problem rather than solve it, so what comes
// back is hashed and checked against what was ASKED FOR — a tag pointing at
// the wrong bytes is an error, not a different build.
func TestPullSourceRefusesBytesThatDoNotHash(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	want := SourceDigest([]byte("the bytes the caller asked for"))
	// Store OTHER bytes under that digest's tag, the way a tampered or
	// mis-tagged mirror would.
	ctx := context.Background()
	repo, err := c.repository("acme.org/thing")
	if err != nil {
		t.Fatal(err)
	}
	other := []byte("something else entirely")
	layer := orascontent.NewDescriptorFromBytes(MediaSourceLayer, other)
	if err := pushIfAbsent(ctx, repo, layer, other); err != nil {
		t.Fatal(err)
	}
	man, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oras.Tag(ctx, repo, man.Digest.String(), SourceTag(want)); err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", want)
	if err == nil || !strings.Contains(err.Error(), "hashing to") {
		t.Errorf("err = %v, want a digest-mismatch refusal", err)
	}
}

// A manifest that is not one layer is not a source archive. Saying so beats
// indexing past the end of a slice.
//
// Note the shape: ORAS packs an EMPTY layer descriptor when given none, so
// "zero layers" is not reachable from here — two is.
func TestPullSourceRefusesAManifestThatIsNotOneLayer(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	repo, err := c.repository("acme.org/thing")
	if err != nil {
		t.Fatal(err)
	}
	var layers []ocispec.Descriptor
	for _, b := range [][]byte{[]byte("one"), []byte("two")} {
		d := orascontent.NewDescriptorFromBytes(MediaSourceLayer, b)
		if err := pushIfAbsent(ctx, repo, d, b); err != nil {
			t.Fatal(err)
		}
		layers = append(layers, d)
	}
	man, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{Layers: layers})
	if err != nil {
		t.Fatal(err)
	}
	dg := SourceDigest([]byte("whatever"))
	if _, err := oras.Tag(ctx, repo, man.Digest.String(), SourceTag(dg)); err != nil {
		t.Fatal(err)
	}
	_, err = c.PullSource("acme.org/thing", dg)
	if err == nil || !strings.Contains(err.Error(), "layers, want 1") {
		t.Errorf("err = %v, want a layer-count refusal", err)
	}
}

// A project name the registry cannot express is an error from every entry
// point, not a panic in one of them.
func TestSourceStoreRejectsAnImpossibleProject(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/sources"))
	if err != nil {
		t.Fatal(err)
	}
	const bad = "UPPER/Not A Repo"
	if _, err := c.PushSource(bad, []byte("x"), ""); err == nil {
		t.Error("PushSource accepted an impossible project name")
	}
	if _, err := c.PullSource(bad, SourceDigest([]byte("x"))); err == nil {
		t.Error("PullSource accepted an impossible project name")
	}
	if _, err := c.HasSource(bad, SourceDigest([]byte("x"))); err == nil {
		t.Error("HasSource accepted an impossible project name")
	}
}

// OCI tags cannot contain a colon.
func TestSourceTagIsAValidTag(t *testing.T) {
	tag := SourceTag(SourceDigest([]byte("x")))
	if strings.Contains(tag, ":") {
		t.Errorf("tag %q contains a colon", tag)
	}
	if !strings.HasPrefix(tag, "sha256-") {
		t.Errorf("tag %q does not name its algorithm", tag)
	}
}

// The failure paths, driven through the fake registry's hook. A mirror that
// cannot be reached must say so; the caller's fallback is the upstream host and
// it needs an error to know to take it.
func TestSourceStoreRegistryFailures(t *testing.T) {
	data := []byte("some source bytes")
	dg := SourceDigest(data)

	t.Run("layer upload fails", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-pkgx/sources"))
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, _ := splitV2(r.URL.Path)
			return 500, verb == "uploads"
		}
		if _, err := c.PushSource("acme.org/thing", data, ""); err == nil {
			t.Error("push reported success with every blob upload failing")
		}
	})

	t.Run("resolve fails for a reason that is not absence", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-pkgx/sources"))
		fr.hook = func(r *http.Request) (int, bool) {
			_, verb, _ := splitV2(r.URL.Path)
			return 500, verb == "manifests"
		}
		_, err := c.PullSource("acme.org/thing", dg)
		if err == nil {
			t.Error("pull reported success against a broken registry")
		}
		if errors.Is(err, ErrSourceAbsent) {
			t.Error("a 500 was reported as a missing source, which would send the caller down the wrong path")
		}
		if _, err := c.HasSource("acme.org/thing", dg); err == nil {
			t.Error("HasSource reported an answer against a broken registry")
		}
	})

	t.Run("the manifest does not parse", func(t *testing.T) {
		fr := newFakeRegistry(t, false)
		defer fr.close()
		c, _ := NewOCIClient(fr.base("go-pkgx/sources"))
		if _, err := c.PushSource("acme.org/thing", data, ""); err != nil {
			t.Fatal(err)
		}
		for k := range fr.manifests {
			fr.manifests[k] = []byte("{not json")
		}
		if _, err := c.PullSource("acme.org/thing", dg); err == nil {
			t.Error("pull accepted a manifest that is not JSON")
		}
	})
}
