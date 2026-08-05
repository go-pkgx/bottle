package bottle

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// pushSignedBottle pushes a bottle whose signature referrer is signed by kp, and
// points the pinned key at kp for the duration of the test.
func pushSignedBottle(t *testing.T, c *OCIClient, project string, kp *sign.Keypair, tarball []byte, withSig bool) {
	t.Helper()
	refs := []Referrer{
		{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: []byte(`{}`)},
	}
	if withSig {
		payload, err := sign.SimpleSigningPayload("pkg:pkgx/"+project, digestOf(tarball))
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, Referrer{
			ArtifactType: ArtifactTypeSignature,
			MediaType:    MediaSimpleSigning,
			Blob:         payload,
			Annotations:  map[string]string{CosignSignatureAnnotation: kp.SignPayload(payload)},
		})
	}
	if _, err := c.PushWithReferrers(project, "1.0.0", "linux", "x86-64", tarball, ".tar.gz", refs); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRequired(t *testing.T) {
	// Empty config so only the injected env drives the decision.
	setConfigPath(t, filepath.Join(t.TempDir(), "absent.hcl2"))
	set := func(v string, present bool) {
		lookupEnv = func(k string) (string, bool) {
			if k == "PKGX_VERIFY" {
				return v, present
			}
			return "", false
		}
	}
	// On by default: the truthy words and any unrecognised value all verify.
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", "maybe"} {
		set(v, true)
		if !VerifyRequired() {
			t.Errorf("PKGX_VERIFY=%q should require verify", v)
		}
	}
	// Unset (absent) also verifies.
	set("", false)
	if !VerifyRequired() {
		t.Error("unset PKGX_VERIFY should require verify")
	}
	// Only an explicit opt-out disables it.
	for _, v := range []string{"0", "false", "FALSE", "off", "no"} {
		set(v, true)
		if VerifyRequired() {
			t.Errorf("PKGX_VERIFY=%q should not require verify", v)
		}
	}
}

func TestVerifyRequiredFromConfig(t *testing.T) {
	// With no env var, the config file value disables verification.
	writeConfig(t, `PKGX_VERIFY = false`)
	setLookup(nil)
	if VerifyRequired() {
		t.Error("config PKGX_VERIFY=false should disable verification")
	}
}

func TestVerifyBottle(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()

	tarball := makeGzTarball("bottle-body")
	pushSignedBottle(t, c, "signed.ok", kp, tarball, true)
	if err := c.VerifyBottle("signed.ok", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Fatalf("valid signed bottle rejected: %v", err)
	}
	// tampered tarball → payload digest mismatch
	if err := c.VerifyBottle("signed.ok", "1.0.0", "linux", "x86-64", makeGzTarball("tampered")); err == nil {
		t.Error("tampered tarball accepted")
	}
	// unsigned bottle → fail closed
	pushSignedBottle(t, c, "unsigned.pkg", kp, tarball, false)
	if err := c.VerifyBottle("unsigned.pkg", "1.0.0", "linux", "x86-64", tarball); err == nil ||
		!strings.Contains(err.Error(), "unsigned") {
		t.Errorf("unsigned bottle: expected fail-closed, got %v", err)
	}
	// missing version → resolve error
	if err := c.VerifyBottle("signed.ok", "9.9.9", "linux", "x86-64", tarball); err == nil {
		t.Error("missing version accepted")
	}
	// bad project → repository() error
	if err := c.VerifyBottle("BAD..name/../x", "1.0.0", "linux", "x86-64", tarball); err == nil {
		t.Error("bad project accepted")
	}
}

func TestVerifyBottleMalformedSig(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	tarball := makeGzTarball("x")
	// a signature referrer with no cosign annotation → malformed
	_, err := c.PushWithReferrers("malformed.sig", "1.0.0", "linux", "x86-64", tarball, ".tar.gz",
		[]Referrer{{ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: []byte(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyBottle("malformed.sig", "1.0.0", "linux", "x86-64", tarball); err == nil ||
		!strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed error, got %v", err)
	}
}

func TestDownloadBottleVerify(t *testing.T) {
	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = oldKey }()

	tarball := makeGzTarball("dl-body")
	pushSignedBottle(t, c, "dl.signed", kp, tarball, true)
	pushSignedBottle(t, c, "dl.unsigned", kp, tarball, false)

	oldDist := DistBase
	DistBase = fr.base("go-pkgx/bottles")
	resetOCICache()
	defer func() { DistBase = oldDist; resetOCICache() }()

	// PKGX_VERIFY + signed OCI bottle → succeeds
	t.Setenv("PKGX_VERIFY", "1")
	if _, _, err := DownloadBottle("dl.signed", "1.0.0", "linux", "x86-64"); err != nil {
		t.Fatalf("signed download+verify: %v", err)
	}
	// PKGX_VERIFY + unsigned OCI bottle → fail closed
	if _, _, err := DownloadBottle("dl.unsigned", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("unsigned bottle passed under PKGX_VERIFY")
	}
	// with verification explicitly opted out (PKGX_VERIFY=0), an unsigned bottle
	// downloads fine (verify is on by default, so this needs the opt-out).
	t.Setenv("PKGX_VERIFY", "0")
	if _, _, err := DownloadBottle("dl.unsigned", "1.0.0", "linux", "x86-64"); err != nil {
		t.Errorf("unverified download: %v", err)
	}
}

func TestVerifyBottleFetchFailures(t *testing.T) {
	kp, _ := sign.Generate()
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	defer func() { SigningPublicKey = old }()
	tarball := makeGzTarball("body")

	cases := map[string]func(method, verb, ref string) bool{
		"referrers":    func(method, verb, ref string) bool { return verb == "referrers" },
		"payload-blob": func(method, verb, ref string) bool { return method == "GET" && verb == "blobs" },
		"platform-man": func(method, verb, ref string) bool {
			return method == "GET" && verb == "manifests" && strings.HasPrefix(ref, "sha256:")
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			fr := newFakeRegistry(t, false)
			defer fr.close()
			c, _ := NewOCIClient(fr.base("go-pkgx/bottles"))
			pushSignedBottle(t, c, "fetch.fail", kp, tarball, true)
			fr.hook = func(r *http.Request) (int, bool) {
				_, verb, ref := splitV2(r.URL.Path)
				return 500, fail(r.Method, verb, ref)
			}
			if err := c.VerifyBottle("fetch.fail", "1.0.0", "linux", "x86-64", tarball); err == nil {
				t.Errorf("%s: expected fetch failure", name)
			}
		})
	}
}

func TestDownloadBottleVerifyHTTP(t *testing.T) {
	oldDist := DistBase
	DistBase = "https://dist.example.test"
	defer func() { DistBase = oldDist }()
	t.Setenv("PKGX_VERIFY", "1")
	// the HTTP transport has no signatures → fail closed before any fetch
	if _, _, err := DownloadBottle("p", "1.0.0", "linux", "x86-64"); err == nil ||
		!strings.Contains(err.Error(), "PKGX_VERIFY") {
		t.Errorf("HTTP under PKGX_VERIFY should fail closed, got %v", err)
	}
}
