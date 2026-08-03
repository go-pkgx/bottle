package bottle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fakeRegistry is an in-memory OCI distribution (registry v2) endpoint used to
// drive the ORAS-backed OCI transport in tests. It speaks enough of the API for
// ORAS to push and pull: /v2/ ping, tags/list, manifests (HEAD/GET/PUT by tag or
// digest), blobs (HEAD/GET) and the monolithic blob-upload flow (POST + PUT). An
// optional Bearer challenge on unauthenticated requests exercises ORAS's
// token-exchange auth path against a separate token endpoint.
type fakeRegistry struct {
	srv        *httptest.Server
	tokenSrv   *httptest.Server
	requireTok bool

	mu        sync.Mutex
	blobs     map[string][]byte // "repo|digest" -> bytes
	manifests map[string][]byte // "repo|ref"    -> bytes (ref = tag or digest)
	mtypes    map[string]string // "repo|ref"    -> media type
	tags      map[string]map[string]bool
	issued    int // token endpoint hits (auth-flow assertion)

	// hook, if set, can force a status code for a request (fault injection).
	hook func(r *http.Request) (status int, fail bool)
}

func newFakeRegistry(t *testing.T, requireTok bool) *fakeRegistry {
	t.Helper()
	fr := &fakeRegistry{
		requireTok: requireTok,
		blobs:      map[string][]byte{},
		manifests:  map[string][]byte{},
		mtypes:     map[string]string{},
		tags:       map[string]map[string]bool{},
	}
	fr.tokenSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.issued++
		fr.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
	}))
	fr.srv = httptest.NewServer(http.HandlerFunc(fr.handle))
	return fr
}

func (fr *fakeRegistry) close() { fr.srv.Close(); fr.tokenSrv.Close() }

// base returns the oci:// dist base for this registry (loopback host → the
// client auto-selects plain HTTP).
func (fr *fakeRegistry) base(repoBase string) string {
	return "oci://" + strings.TrimPrefix(fr.srv.URL, "http://") + "/" + repoBase
}

func sha256hex(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

// splitV2 parses /v2/<repo>/<verb>[/<ref>].
func splitV2(p string) (repo, verb, ref string) {
	p = strings.TrimPrefix(p, "/v2/")
	for _, v := range []string{"/manifests/", "/blobs/uploads/", "/blobs/", "/tags/list", "/referrers/"} {
		if i := strings.Index(p, v); i >= 0 {
			repo = p[:i]
			rest := p[i:]
			switch {
			case strings.HasPrefix(rest, "/tags/list"):
				return repo, "tags", ""
			case strings.HasPrefix(rest, "/referrers/"):
				return repo, "referrers", strings.TrimPrefix(rest, "/referrers/")
			case strings.HasPrefix(rest, "/manifests/"):
				return repo, "manifests", strings.TrimPrefix(rest, "/manifests/")
			case strings.HasPrefix(rest, "/blobs/uploads/"):
				return repo, "uploads", strings.TrimPrefix(rest, "/blobs/uploads/")
			case strings.HasPrefix(rest, "/blobs/"):
				return repo, "blobs", strings.TrimPrefix(rest, "/blobs/")
			}
		}
	}
	return "", "", ""
}

func (fr *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2/" || r.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if fr.hook != nil {
		if status, fail := fr.hook(r); fail {
			http.Error(w, "forced fault", status)
			return
		}
	}
	if fr.requireTok && r.Header.Get("Authorization") != "Bearer test-token" {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:x:pull,push"`, fr.tokenSrv.URL))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	fr.mu.Lock()
	defer fr.mu.Unlock()
	repo, verb, ref := splitV2(r.URL.Path)
	switch verb {
	case "tags":
		set := fr.tags[repo]
		if set == nil {
			http.NotFound(w, r)
			return
		}
		var tags []string
		for t := range set {
			tags = append(tags, t)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": tags})
	case "referrers":
		// Serve the OCI referrers API: an image index of every stored manifest
		// whose subject digest is ref (as ghcr does).
		var manifests []ocispec.Descriptor
		seen := map[string]bool{}
		for key, body := range fr.manifests {
			i := strings.IndexByte(key, '|')
			if i < 0 || key[:i] != repo {
				continue
			}
			id := key[i+1:]
			if !strings.HasPrefix(id, "sha256:") || seen[id] {
				continue
			}
			var m ocispec.Manifest
			if json.Unmarshal(body, &m) != nil || m.Subject == nil || m.Subject.Digest.String() != ref {
				continue
			}
			seen[id] = true
			manifests = append(manifests, ocispec.Descriptor{
				MediaType:    fr.mtypes[key],
				ArtifactType: m.ArtifactType,
				Digest:       digest.Digest(id),
				Size:         int64(len(body)),
			})
		}
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 2,
			"mediaType":     ocispec.MediaTypeImageIndex,
			"manifests":     manifests,
		})
	case "manifests":
		key := repo + "|" + ref
		switch r.Method {
		case "HEAD", "GET":
			body, ok := fr.manifests[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", fr.mtypes[key])
			w.Header().Set("Docker-Content-Digest", sha256hex(body))
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			if r.Method == "GET" {
				w.Write(body)
			}
		case "PUT":
			body, _ := io.ReadAll(r.Body)
			dg := sha256hex(body)
			fr.manifests[key] = body
			fr.mtypes[key] = r.Header.Get("Content-Type")
			fr.manifests[repo+"|"+dg] = body
			fr.mtypes[repo+"|"+dg] = r.Header.Get("Content-Type")
			if !strings.HasPrefix(ref, "sha256:") {
				if fr.tags[repo] == nil {
					fr.tags[repo] = map[string]bool{}
				}
				fr.tags[repo][ref] = true
			}
			// Advertise referrers-API support: echo OCI-Subject when the pushed
			// manifest carries a subject, so ORAS skips fallback-tag maintenance
			// (matches a spec-compliant registry such as ghcr).
			var m ocispec.Manifest
			if json.Unmarshal(body, &m) == nil && m.Subject != nil {
				w.Header().Set("OCI-Subject", m.Subject.Digest.String())
			}
			w.Header().Set("Docker-Content-Digest", dg)
			w.WriteHeader(http.StatusCreated)
		case "DELETE":
			delete(fr.manifests, key)
			w.WriteHeader(http.StatusAccepted)
		}
	case "blobs":
		key := repo + "|" + ref
		b, ok := fr.blobs[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		if r.Method == "GET" {
			w.Write(b)
		}
	case "uploads":
		switch r.Method {
		case "POST":
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/u1", repo))
			w.Header().Set("Docker-Upload-UUID", "u1")
			w.WriteHeader(http.StatusAccepted)
		case "PUT":
			body, _ := io.ReadAll(r.Body)
			dg := r.URL.Query().Get("digest")
			fr.blobs[repo+"|"+dg] = body
			w.Header().Set("Docker-Content-Digest", dg)
			w.WriteHeader(http.StatusCreated)
		}
	default:
		http.NotFound(w, r)
	}
}

func makeGzTarball(marker string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(marker))
	gz.Close()
	return buf.Bytes()
}

// resetOCICache clears the memoised OCIClients so a DistBase change rebuilds the
// client.
func resetOCICache() {
	ociClientMu.Lock()
	ociClientCache = map[string]*OCIClient{}
	ociClientMu.Unlock()
}

func TestOCIRoundTripPushPull(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	base := fr.base("go-pkgx/bottles")

	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	gzData := makeGzTarball("hello-linux-amd64")
	if err := c.Push("hello.test", "1.2.3", "linux", "x86-64", gzData, ".tar.gz"); err != nil {
		t.Fatalf("push linux/x86-64: %v", err)
	}
	xzMarker := []byte("hello-darwin-arm64-xz")
	if err := c.Push("hello.test", "1.2.3", "darwin", "aarch64", xzMarker, ".tar.xz"); err != nil {
		t.Fatalf("push darwin/aarch64: %v", err)
	}

	old := DistBase
	DistBase = base
	defer func() { DistBase = old; resetOCICache() }()
	resetOCICache()

	vs, err := VersionsFor("hello.test", "linux", "x86-64")
	if err != nil || len(vs) != 1 || vs[0].Raw != "1.2.3" {
		t.Fatalf("VersionsFor = %v err=%v", vs, err)
	}
	got, ext, err := DownloadBottle("hello.test", "1.2.3", "linux", "x86-64")
	if err != nil || ext != ".tar.gz" {
		t.Fatalf("DownloadBottle linux ext=%q err=%v", ext, err)
	}
	if !bytes.Equal(got, gzData) {
		t.Errorf("linux bytes mismatch: got %d bytes", len(got))
	}
	// the other platform selects the xz layer + exact bytes.
	got2, ext2, err := DownloadBottle("hello.test", "1.2.3", "darwin", "aarch64")
	if err != nil || ext2 != ".tar.xz" {
		t.Fatalf("DownloadBottle darwin ext=%q err=%v", ext2, err)
	}
	if !bytes.Equal(got2, xzMarker) {
		t.Errorf("darwin bytes mismatch")
	}
	// a platform not pushed → error (platform not in index).
	if _, _, err := DownloadBottle("hello.test", "1.2.3", "windows", "x86-64"); err == nil {
		t.Error("expected error for a platform absent from the index")
	}
}

func TestOCIAuthChallengeFlow(t *testing.T) {
	fr := newFakeRegistry(t, true) // require bearer token
	defer fr.close()
	base := fr.base("go-pkgx/bottles")
	c, err := NewOCIClient(base)
	if err != nil {
		t.Fatal(err)
	}
	data := makeGzTarball("auth-flow")
	if err := c.Push("secure.test", "0.1.0", "linux", "x86-64", data, ".tar.gz"); err != nil {
		t.Fatalf("push under auth: %v", err)
	}
	fr.mu.Lock()
	issued := fr.issued
	fr.mu.Unlock()
	if issued == 0 {
		t.Error("expected the token endpoint to be exercised")
	}
	old := DistBase
	DistBase = base
	defer func() { DistBase = old; resetOCICache() }()
	resetOCICache()
	got, _, err := DownloadBottle("secure.test", "0.1.0", "linux", "x86-64")
	if err != nil {
		t.Fatalf("authed pull: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("authed pull byte mismatch")
	}
}

func TestOCIListVersionsMissingRepo(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	old := DistBase
	DistBase = fr.base("go-pkgx/bottles")
	defer func() { DistBase = old; resetOCICache() }()
	resetOCICache()
	if _, err := VersionsFor("nope.test", "linux", "x86-64"); err == nil {
		t.Error("expected error for an unknown repo")
	}
}

func TestOCIRepushIsIdempotent(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	data := makeGzTarball("idem")
	if err := c.Push("idem.test", "1.0.0", "linux", "x86-64", data, ".tar.gz"); err != nil {
		t.Fatal(err)
	}
	// second push of the same bottle must not error (Exists short-circuit).
	if err := c.Push("idem.test", "1.0.0", "linux", "x86-64", data, ".tar.gz"); err != nil {
		t.Fatalf("re-push: %v", err)
	}
}

func TestNewOCIClientParsing(t *testing.T) {
	cases := []struct {
		base, host, repo string
		plain            bool
	}{
		{"oci://ghcr.io/go-pkgx/bottles", "ghcr.io", "go-pkgx/bottles", false},
		{"oci://localhost:5000/x/y", "localhost:5000", "x/y", true},
		{"oci://127.0.0.1:8080/b", "127.0.0.1:8080", "b", true},
		{"oci://http://reg.internal/b", "reg.internal", "b", true},
		{"oci://https://localhost:5000/b", "localhost:5000", "b", false}, // explicit https wins over loopback
		{"oci://REG.io/UPPER/Path", "REG.io", "upper/path", false},       // repo lowercased
	}
	for _, tc := range cases {
		c, err := newOCIClientEnv(tc.base, func(string) string { return "" })
		if err != nil {
			t.Fatalf("%s: %v", tc.base, err)
		}
		if c.host != tc.host || c.repoBase != tc.repo || c.plainHTTP != tc.plain {
			t.Errorf("%s -> host=%q repo=%q plain=%v", tc.base, c.host, c.repoBase, c.plainHTTP)
		}
	}
	c, _ := newOCIClientEnv("oci://ghcr.io/go-pkgx/bottles", func(string) string { return "" })
	if got := c.repoName("OpenSSL.org"); got != "go-pkgx/bottles/openssl.org" {
		t.Errorf("repoName() = %q", got)
	}
	if _, err := NewOCIClient("https://not-oci"); err == nil {
		t.Error("want error for non-oci base")
	}
	if _, err := newOCIClientEnv("oci://hostonly", func(string) string { return "" }); err == nil {
		t.Error("want error for missing repo path")
	}
	// credential env variants build without panicking.
	if _, err := newOCIClientEnv("oci://ghcr.io/x/y", func(k string) string {
		if k == "OCI_TOKEN" {
			return "tok"
		}
		return ""
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := newOCIClientEnv("oci://ghcr.io/x/y", func(k string) string {
		if k == "OCI_USERNAME" {
			return "u"
		}
		return ""
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOCIArchMapping(t *testing.T) {
	if ociArch("x86-64") != "amd64" || ociArch("aarch64") != "arm64" || ociArch("riscv64") != "riscv64" {
		t.Error("ociArch mapping")
	}
	if pkgxArch("amd64") != "x86-64" || pkgxArch("arm64") != "aarch64" || pkgxArch("ppc64le") != "ppc64le" {
		t.Error("pkgxArch mapping")
	}
}

func TestExtForLayerVariants(t *testing.T) {
	cases := map[string]string{
		MediaBottleLayerGz:             ".tar.gz",
		MediaBottleLayerXz:             ".tar.xz",
		"application/x-foo.tar+gzip":   ".tar.gz",
		"application/x-foo.tar+xz":     ".tar.xz",
		"application/gzip":             ".tar.gz",
		"application/x-xz":             ".tar.xz",
		"application/vnd.example+json": "",
	}
	for mt, want := range cases {
		if got := extForLayer(mt); got != want {
			t.Errorf("extForLayer(%q)=%q want %q", mt, got, want)
		}
	}
}

func TestIsIndexMediaSniff(t *testing.T) {
	// by descriptor media type
	if !isIndexMedia("application/vnd.oci.image.index.v1+json", nil) {
		t.Error("index by mediaType")
	}
	if isIndexMedia("application/vnd.oci.image.manifest.v1+json", nil) {
		t.Error("manifest wrongly detected as index")
	}
	// by body sniff (empty content type)
	idx := []byte(`{"mediaType":"application/vnd.oci.image.index.v1+json"}`)
	if !isIndexMedia("", idx) {
		t.Error("index sniff by body mediaType")
	}
	man := []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)
	if isIndexMedia("", man) {
		t.Error("manifest body sniff wrong")
	}
	// docker manifest list
	if !isIndexMedia("application/vnd.docker.distribution.manifest.list.v2+json", nil) {
		t.Error("docker manifest list not detected")
	}
}

func TestOCIPushReferrers(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, err := NewOCIClient(fr.base("go-pkgx/bottles"))
	if err != nil {
		t.Fatal(err)
	}
	tarball := makeGzTarball("bottle-body")
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)
	prov := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	manDesc, err := c.PushWithReferrers("ref.test", "1.0.0", "linux", "x86-64", tarball, ".tar.gz",
		[]Referrer{
			{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: sbom},
			{ArtifactType: "application/vnd.in-toto+json", MediaType: "application/vnd.in-toto+json", Blob: prov,
				Annotations: map[string]string{"dev.cosignproject.cosign/signature": "sig123"}},
		})
	if err != nil {
		t.Fatalf("PushWithReferrers: %v", err)
	}
	refs, err := c.Referrers("ref.test", manDesc)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("referrers = %d, want 2", len(refs))
	}
	got := map[string]bool{}
	for _, r := range refs {
		got[r.ArtifactType] = true
	}
	if !got["application/vnd.cyclonedx+json"] || !got["application/vnd.in-toto+json"] {
		t.Errorf("referrer artifact types = %v", got)
	}
	// the bottle itself is still pullable
	if _, _, err := c.Pull("ref.test", "1.0.0", "linux", "x86-64"); err != nil {
		t.Errorf("bottle not pullable after referrers: %v", err)
	}
}

func TestOCIReferrerBlobFailure(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	sbom := []byte(`{"bomFormat":"CycloneDX"}`)
	sbomDigest := sha256hex(sbom)
	// fail exactly the referrer blob upload → pushReferrer blob error → push error
	fr.hook = func(r *http.Request) (int, bool) {
		return http.StatusInternalServerError, r.Method == "PUT" && r.URL.Query().Get("digest") == sbomDigest
	}
	if _, err := c.PushWithReferrers("blob.fail", "1", "linux", "x86-64", makeGzTarball("x"), ".tar.gz",
		[]Referrer{{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: sbom}}); err == nil {
		t.Error("expected referrer blob push failure")
	}
}

func TestOCIReferrersServerError(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	manDesc, err := c.PushWithReferrers("srv.err", "1", "linux", "x86-64", makeGzTarball("y"), ".tar.gz", nil)
	if err != nil {
		t.Fatal(err)
	}
	fr.hook = func(r *http.Request) (int, bool) {
		_, verb, _ := splitV2(r.URL.Path)
		return http.StatusInternalServerError, verb == "referrers"
	}
	if _, err := c.Referrers("srv.err", manDesc); err == nil {
		t.Error("expected referrers listing error")
	}
}

func TestOCIReferrersErrors(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	// a bad project name makes repository() (remote.NewRepository) fail for both
	// pushReferrer's caller and Referrers.
	bad := "BAD..name/../x"
	if _, err := c.PushWithReferrers(bad, "1", "linux", "x86-64", makeGzTarball("x"), ".tar.gz",
		[]Referrer{{ArtifactType: "a", MediaType: "a", Blob: []byte("b")}}); err == nil {
		t.Error("expected push error for bad project")
	}
	if _, err := c.Referrers(bad, ocispec.Descriptor{Digest: digest.Digest("sha256:" + strings.Repeat("a", 64))}); err == nil {
		t.Error("expected referrers error for bad project")
	}
}

func TestUpsertPlatform(t *testing.T) {
	desc := func(dg, os, arch string) ocispec.Descriptor {
		return ocispec.Descriptor{Digest: digest.Digest(dg), Platform: &ocispec.Platform{OS: os, Architecture: arch}}
	}
	list := []ocispec.Descriptor{desc("a", "linux", "amd64"), desc("b", "linux", "arm64")}
	list = upsertPlatform(list, desc("a2", "linux", "amd64")) // replace amd64
	if len(list) != 2 {
		t.Fatalf("len=%d", len(list))
	}
	for _, m := range list {
		if m.Platform.Architecture == "amd64" && string(m.Digest) != "a2" {
			t.Errorf("amd64 not replaced: %q", m.Digest)
		}
	}
	list = upsertPlatform(list, desc("c", "darwin", "arm64")) // add new platform
	if len(list) != 3 {
		t.Errorf("expected 3 platforms, got %d", len(list))
	}
}
