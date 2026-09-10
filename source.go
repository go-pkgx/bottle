package bottle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// A source mirror: the bytes a bottle was BUILT FROM, stored in a registry so a
// rebuild does not depend on an upstream host answering.
//
// This matters more than "upstream might go away". 57% of the pkgx pantry is
// built from GitHub `/archive/refs/tags/…` tarballs, which are GENERATED on
// request rather than stored: of 165 such URLs probed, not one advertises a
// Content-Length, because the object does not exist until someone asks. The
// compression pipeline behind them has changed before and every checksum in the
// ecosystem changed with it. A mirror of those is not a copy of anything — it is
// the first and only stored artefact those sources have ever had.
//
// Addressed by CONTENT, not by URL. `SourceTag` turns the sha256 the fetcher
// already computed into the tag, so the digest recorded in a bottle's SBOM IS
// the address of the bytes, and nothing has to be named twice or kept in step.
const (
	// MediaSourceLayer marks the stored archive. Deliberately codec-agnostic:
	// what is stored is the upstream bytes exactly as they arrived, whatever
	// they were compressed with, because changing a byte would change the digest
	// that is the whole point.
	MediaSourceLayer = "application/vnd.pkgx.source.layer.v1"
	// ArtifactTypeSource marks a source manifest, so a registry listing can tell
	// these from bottles.
	ArtifactTypeSource = "application/vnd.pkgx.source"

	// AnnotationSourceURI records where the bytes came from. It is provenance,
	// not an address: two URLs can serve the same bytes and the digest is what
	// identifies them.
	AnnotationSourceURI = "dev.pkgx.source.uri"
)

// ErrSourceAbsent is returned by PullSource when the store has no such digest.
var ErrSourceAbsent = errors.New("bottle: source not in the mirror")

// SourceTag is the registry tag for a source digest. OCI tags cannot contain a
// colon, so `sha256:abcd…` becomes `sha256-abcd…` — the same substitution the
// referrers fallback uses.
func SourceTag(sha256hex string) string { return "sha256-" + sha256hex }

// SourceDigest is the sha256 of data in lowercase hex, the form SourceTag takes
// and the form a bottle's SBOM records.
func SourceDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PushSource stores one source archive under project:sha256-<digest>.
//
// Idempotent by construction: the tag IS the content, so re-pushing the same
// bytes writes the same manifest. uri is recorded as an annotation for whoever
// later asks where this came from.
func (c *OCIClient) PushSource(project string, data []byte, uri string) (ocispec.Descriptor, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	layerDesc := orascontent.NewDescriptorFromBytes(MediaSourceLayer, data)
	if err := pushIfAbsent(ctx, repo, layerDesc, data); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push source layer: %w", err)
	}
	ann := map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"}
	if uri != "" {
		ann[AnnotationSourceURI] = uri
	}
	manDesc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeSource,
		oras.PackManifestOptions{
			Layers:              []ocispec.Descriptor{layerDesc},
			ManifestAnnotations: ann,
		})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack source manifest: %w", err)
	}
	if _, err := oras.Tag(ctx, repo, manDesc.Digest.String(), SourceTag(SourceDigest(data))); err != nil {
		return manDesc, fmt.Errorf("tag source manifest: %w", err)
	}
	return manDesc, nil
}

// PullSource fetches the archive stored for a sha256 digest, and VERIFIES that
// what came back hashes to it.
//
// The verification is not ceremony. A mirror exists so a rebuild need not trust
// the upstream host; trusting the mirror instead would move the problem rather
// than solve it. The digest is checked against the one the caller asked for, so
// a wrong or tampered blob is an error rather than a different build.
func (c *OCIClient) PullSource(project, sha256hex string) ([]byte, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	manDesc, err := repo.Resolve(ctx, SourceTag(sha256hex))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s %s", ErrSourceAbsent, project, sha256hex)
		}
		return nil, err
	}
	manBytes, err := orascontent.FetchAll(ctx, repo, manDesc)
	if err != nil {
		return nil, err
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return nil, fmt.Errorf("source manifest %s: %w", sha256hex, err)
	}
	if len(man.Layers) != 1 {
		return nil, fmt.Errorf("source manifest %s: %d layers, want 1", sha256hex, len(man.Layers))
	}
	data, err := orascontent.FetchAll(ctx, repo, man.Layers[0])
	if err != nil {
		return nil, err
	}
	if got := SourceDigest(data); got != sha256hex {
		return nil, fmt.Errorf("source %s: mirror returned bytes hashing to %s", sha256hex, got)
	}
	return data, nil
}

// HasSource reports whether the store already holds a digest, without fetching
// it — what a populate step asks before uploading megabytes for nothing.
func (c *OCIClient) HasSource(project, sha256hex string) (bool, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return false, err
	}
	if _, err := repo.Resolve(ctx, SourceTag(sha256hex)); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
