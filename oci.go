package bottle

// OCI-registry transport for pkgx bottles, backed by the ORAS/CNCF Go library
// (oras.land/oras-go/v2) — the reference implementation for pulling and pushing
// OCI artifacts. Pure Go, CGO_ENABLED=0.
//
// A dist ref beginning with "oci://" (e.g. PKGX_DIST=oci://ghcr.io/go-pkgx/bottles)
// selects this transport instead of the static-HTTP tree. Bottles are mapped to
// OCI artifacts Homebrew-style:
//
//   - repo   = <oci-base-repo>/<project>            (project lowercased; OCI repos
//              allow '/' and '.'). e.g. go-pkgx/bottles/openssl.org
//   - tag    = the version                          (e.g. "1.1.1w")
//   - the manifest at that tag is an OCI image INDEX whose manifests[] each carry
//     platform{os,architecture} and point at a per-platform image manifest.
//   - each per-platform image manifest has a (scratch) config blob + ONE layer =
//     the bottle tarball (layer mediaType application/vnd.pkgx.bottle.layer.v1.tar+gzip
//     or +xz).
//
// pkgx arch slugs (x86-64 / aarch64) map to OCI/Go names (amd64 / arm64); os
// names (linux / darwin / windows) are shared. ORAS handles the registry v2
// wire protocol (blob/manifest CAS) and anonymous/bearer/basic auth (including
// ghcr.io and Docker Hub token exchange) for us.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// OCI / pkgx media types.
const (
	MediaBottleLayerGz = "application/vnd.pkgx.bottle.layer.v1.tar+gzip"
	MediaBottleLayerXz = "application/vnd.pkgx.bottle.layer.v1.tar+xz"
	// ArtifactTypeBottle marks a pkgx-bottle image manifest (its manifest.config
	// carries this via ORAS PackManifest v1.1's artifactType).
	ArtifactTypeBottle = "application/vnd.pkgx.bottle"
	// dockerManifestList is Docker's media type for a multi-platform index, which
	// some registries (Docker Hub) return instead of the OCI image index.
	dockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// IsOCI reports whether a dist base selects the OCI transport.
func IsOCI(base string) bool { return strings.HasPrefix(base, "oci://") }

// --- arch mapping -----------------------------------------------------------

// ociArch maps a pkgx arch slug to the OCI/Go architecture name.
func ociArch(arch string) string {
	switch arch {
	case "x86-64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return arch
	}
}

// pkgxArch maps an OCI/Go architecture name back to the pkgx arch slug.
func pkgxArch(arch string) string {
	switch arch {
	case "amd64":
		return "x86-64"
	case "arm64":
		return "aarch64"
	default:
		return arch
	}
}

// extForLayer maps a bottle layer mediaType to a file extension, or "" for a
// layer (e.g. the config blob) we don't recognise as a bottle tarball.
func extForLayer(mt string) string {
	switch {
	case strings.HasSuffix(mt, "tar+gzip"), strings.HasSuffix(mt, "tar.gzip"):
		return ".tar.gz"
	case strings.HasSuffix(mt, "tar+xz"):
		return ".tar.xz"
	case strings.Contains(mt, "gzip"):
		return ".tar.gz"
	case strings.Contains(mt, "xz"):
		return ".tar.xz"
	default:
		return ""
	}
}

// --- client -----------------------------------------------------------------

// OCIClient talks to an OCI distribution (registry v2) endpoint via ORAS. It is
// used by the bottle pull path and by the mirror push tool, so the OCI protocol
// lives in one place (ORAS).
type OCIClient struct {
	host      string // registry host[:port]
	repoBase  string // base repo path within the registry, e.g. "go-pkgx/bottles"
	plainHTTP bool   // use http:// (localhost/loopback or explicit http scheme)
	client    *auth.Client
}

// NewOCIClient parses an oci:// dist base into a client. Localhost/loopback
// hosts default to plain HTTP (for a local zot/registry on a port); every other
// host uses HTTPS. Credentials are read from the environment: OCI_TOKEN (a
// pre-issued bearer), else OCI_USERNAME / OCI_PASSWORD for token exchange /
// basic auth. Public repositories work anonymously.
func NewOCIClient(base string) (*OCIClient, error) {
	return newOCIClientEnv(base, os.Getenv)
}

func newOCIClientEnv(base string, getenv func(string) string) (*OCIClient, error) {
	if !IsOCI(base) {
		return nil, fmt.Errorf("not an oci:// ref: %q", base)
	}
	rest := strings.TrimRight(strings.TrimPrefix(base, "oci://"), "/")
	// Allow an explicit scheme hint via a leading http://|https://.
	plainHint, forcedHTTP := false, false
	switch {
	case strings.HasPrefix(rest, "http://"):
		rest, plainHint, forcedHTTP = strings.TrimPrefix(rest, "http://"), true, true
	case strings.HasPrefix(rest, "https://"):
		rest, forcedHTTP = strings.TrimPrefix(rest, "https://"), true
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return nil, fmt.Errorf("oci ref %q has no repository path", base)
	}
	host := rest[:slash]
	repoBase := strings.Trim(rest[slash+1:], "/")
	if host == "" || repoBase == "" {
		return nil, fmt.Errorf("oci ref %q missing host or repo", base)
	}
	plainHTTP := plainHint
	if !forcedHTTP && isLoopback(host) {
		plainHTTP = true
	}
	tok := getenv("OCI_TOKEN")
	user := getenv("OCI_USERNAME")
	pass := getenv("OCI_PASSWORD")
	cred := auth.Credential{}
	switch {
	case tok != "":
		cred.AccessToken = tok
	case user != "" || pass != "":
		cred.Username, cred.Password = user, pass
	}
	ac := &auth.Client{
		Client: HTTPClient,
		Cache:  auth.NewCache(),
	}
	if cred != (auth.Credential{}) {
		ac.Credential = func(_ context.Context, _ string) (auth.Credential, error) { return cred, nil }
	}
	return &OCIClient{
		host:      host,
		repoBase:  strings.ToLower(repoBase),
		plainHTTP: plainHTTP,
		client:    ac,
	}, nil
}

// isLoopback reports whether host (possibly host:port) is a loopback address,
// for which we default to plain HTTP.
func isLoopback(host string) bool {
	h := host
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	h = strings.Trim(h, "[]")
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// repoName returns the OCI repository path for a pkgx project (lowercased).
func (c *OCIClient) repoName(project string) string {
	return c.repoBase + "/" + strings.ToLower(project)
}

// repository builds an ORAS remote.Repository for a project.
func (c *OCIClient) repository(project string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(c.host + "/" + c.repoName(project))
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = c.plainHTTP
	repo.Client = c.client
	return repo, nil
}

// --- pull -------------------------------------------------------------------

// ListTags returns the tags (versions) published for a project, or an error if
// the repository does not exist.
func (c *OCIClient) ListTags(project string) ([]string, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	var tags []string
	err = repo.Tags(context.Background(), "", func(page []string) error {
		tags = append(tags, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tags, nil
}

// Pull downloads the bottle tarball for a project/version/os/arch: fetch the
// version-tag manifest (an index, or a single-platform image manifest), pick the
// platform-matching image manifest, take its single non-config layer, fetch the
// layer blob. Returns the tarball bytes and the extension (".tar.gz"/".tar.xz")
// derived from the layer mediaType.
func (c *OCIClient) Pull(project, ver, osn, arch string) ([]byte, string, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return nil, "", err
	}
	tagDesc, rc, err := repo.FetchReference(ctx, ver)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s v%s: %w", project, ver, err)
	}
	body, err := orascontent.ReadAll(rc, tagDesc)
	rc.Close()
	if err != nil {
		return nil, "", err
	}
	// The tag resolves to an index (multi-platform) or directly to an image
	// manifest (single-platform push).
	manBytes := body
	if isIndexMedia(tagDesc.MediaType, body) {
		var idx ocispec.Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return nil, "", err
		}
		wantArch := ociArch(arch)
		var pick *ocispec.Descriptor
		for i := range idx.Manifests {
			m := idx.Manifests[i]
			if m.Platform != nil && m.Platform.OS == osn && m.Platform.Architecture == wantArch {
				pick = &m
				break
			}
		}
		if pick == nil {
			return nil, "", fmt.Errorf("no bottle for %s v%s (%s/%s): platform not in index", project, ver, osn, arch)
		}
		manBytes, err = orascontent.FetchAll(ctx, repo, *pick)
		if err != nil {
			return nil, "", err
		}
	}
	var man ocispec.Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return nil, "", err
	}
	for _, l := range man.Layers {
		ext := extForLayer(l.MediaType)
		if ext == "" {
			continue
		}
		data, err := orascontent.FetchAll(ctx, repo, l)
		if err != nil {
			return nil, "", err
		}
		return data, ext, nil
	}
	return nil, "", fmt.Errorf("no bottle layer for %s v%s (%s/%s)", project, ver, osn, arch)
}

// isIndexMedia reports whether a manifest is an image index, by descriptor
// mediaType when set, else by sniffing the JSON body.
func isIndexMedia(mediaType string, body []byte) bool {
	switch mediaType {
	case ocispec.MediaTypeImageIndex, dockerManifestList:
		return true
	case ocispec.MediaTypeImageManifest:
		return false
	}
	var probe struct {
		MediaType string `json:"mediaType"`
		Manifests []any  `json:"manifests"`
	}
	_ = json.Unmarshal(body, &probe)
	if probe.MediaType == ocispec.MediaTypeImageIndex || probe.MediaType == dockerManifestList {
		return true
	}
	return len(probe.Manifests) > 0
}

// --- push -------------------------------------------------------------------

// Referrer is an attestation to attach to a bottle's per-platform manifest as an
// OCI referrer (subject-linked artifact): a CycloneDX/SPDX SBOM, an in-toto SLSA
// provenance statement, or (later) a cosign signature. ArtifactType classifies
// the referrer manifest; MediaType is the layer blob's media type (usually the
// same); Blob is the attestation bytes.
type Referrer struct {
	ArtifactType string
	MediaType    string
	Blob         []byte
}

// Push publishes one bottle for a project/version/os/arch: it pushes the tarball
// as a layer blob, packs a per-platform image manifest (ORAS PackManifest, which
// also pushes a scratch config blob), then merges the platform into the
// version-tag image index (fetching any existing index first) and tags it. ext
// selects the layer mediaType (".tar.gz" or ".tar.xz").
func (c *OCIClient) Push(project, ver, osn, arch string, tarball []byte, ext string) error {
	_, err := c.push(project, ver, osn, arch, tarball, ext, nil)
	return err
}

// PushWithReferrers is Push plus a set of attestations attached to the pushed
// per-platform manifest as OCI referrers. It returns that manifest's descriptor
// so callers can list/verify the referrers. Referrers are pushed before the
// version index is tagged, so a reader that resolves the index always finds a
// manifest whose attestations are already present.
func (c *OCIClient) PushWithReferrers(project, ver, osn, arch string, tarball []byte, ext string, refs []Referrer) (ocispec.Descriptor, error) {
	return c.push(project, ver, osn, arch, tarball, ext, refs)
}

func (c *OCIClient) push(project, ver, osn, arch string, tarball []byte, ext string, refs []Referrer) (ocispec.Descriptor, error) {
	ctx := context.Background()
	repo, err := c.repository(project)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	layerMedia := MediaBottleLayerGz
	if ext == ".tar.xz" {
		layerMedia = MediaBottleLayerXz
	}
	layerDesc := orascontent.NewDescriptorFromBytes(layerMedia, tarball)
	if err := pushIfAbsent(ctx, repo, layerDesc, tarball); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push layer: %w", err)
	}
	// Pack + push a per-platform image manifest (config blob is created by ORAS).
	manDesc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, ArtifactTypeBottle,
		oras.PackManifestOptions{
			Layers: []ocispec.Descriptor{layerDesc},
			// pin a fixed created-time so the manifest digest is reproducible.
			ManifestAnnotations: map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"},
		})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	manDesc.Platform = &ocispec.Platform{OS: osn, Architecture: ociArch(arch)}
	// Attach attestations as referrers of the platform manifest.
	for _, rf := range refs {
		if err := c.pushReferrer(ctx, repo, manDesc, rf); err != nil {
			return manDesc, fmt.Errorf("push referrer %s: %w", rf.ArtifactType, err)
		}
	}
	// Merge the platform into the version-tag index and re-tag.
	idx := c.fetchOrNewIndex(ctx, repo, ver)
	idx.Manifests = upsertPlatform(idx.Manifests, manDesc)
	idxBytes, err := json.Marshal(idx)
	if err != nil {
		return manDesc, err
	}
	if _, err := oras.TagBytes(ctx, repo, ocispec.MediaTypeImageIndex, idxBytes, ver); err != nil {
		return manDesc, fmt.Errorf("tag index: %w", err)
	}
	return manDesc, nil
}

// pushReferrer pushes one attestation blob and an artifact manifest that links
// it to subject via the OCI subject field (a referrer). On registries with the
// referrers API (ghcr) it is discoverable via Referrers.
func (c *OCIClient) pushReferrer(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor, rf Referrer) error {
	blobDesc := orascontent.NewDescriptorFromBytes(rf.MediaType, rf.Blob)
	if err := pushIfAbsent(ctx, repo, blobDesc, rf.Blob); err != nil {
		return err
	}
	subj := subject
	_, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, rf.ArtifactType,
		oras.PackManifestOptions{
			Subject:             &subj,
			Layers:              []ocispec.Descriptor{blobDesc},
			ManifestAnnotations: map[string]string{ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"},
		})
	return err
}

// Referrers lists the attestations attached to a manifest (its OCI referrers),
// each descriptor carrying the referrer's ArtifactType.
func (c *OCIClient) Referrers(project string, subject ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	repo, err := c.repository(project)
	if err != nil {
		return nil, err
	}
	var out []ocispec.Descriptor
	err = repo.Referrers(context.Background(), subject, "", func(page []ocispec.Descriptor) error {
		out = append(out, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// pushIfAbsent pushes content only when the registry does not already hold it,
// so re-pushing an existing bottle is a no-op (and avoids EEXIST on registries
// that reject duplicate blob PUTs).
func pushIfAbsent(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, data []byte) error {
	if ok, err := repo.Exists(ctx, desc); err == nil && ok {
		return nil
	}
	if err := repo.Push(ctx, desc, strings.NewReader(string(data))); err != nil {
		// A concurrent push may have raced us; treat an already-exists as success.
		if ok, e := repo.Exists(ctx, desc); e == nil && ok {
			return nil
		}
		return err
	}
	return nil
}

// fetchOrNewIndex returns the existing version-tag index, or a fresh empty one
// if the tag does not yet exist (or resolves to a non-index manifest).
func (c *OCIClient) fetchOrNewIndex(ctx context.Context, repo *remote.Repository, ver string) ocispec.Index {
	fresh := ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
	}
	desc, rc, err := repo.FetchReference(ctx, ver)
	if err != nil {
		return fresh
	}
	body, err := orascontent.ReadAll(rc, desc)
	rc.Close()
	if err != nil || !isIndexMedia(desc.MediaType, body) {
		return fresh
	}
	var idx ocispec.Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return fresh
	}
	idx.Versioned = specs.Versioned{SchemaVersion: 2}
	idx.MediaType = ocispec.MediaTypeImageIndex
	return idx
}

// upsertPlatform adds desc to a manifest list, replacing any existing entry for
// the same os/architecture.
func upsertPlatform(list []ocispec.Descriptor, desc ocispec.Descriptor) []ocispec.Descriptor {
	out := list[:0]
	for _, m := range list {
		if m.Platform != nil && desc.Platform != nil &&
			m.Platform.OS == desc.Platform.OS && m.Platform.Architecture == desc.Platform.Architecture {
			continue // drop the old entry for this platform
		}
		out = append(out, m)
	}
	return append(out, desc)
}
