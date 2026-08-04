package bottle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-attest/sign"
)

// osGetenv is os.Getenv, swappable in tests.
var osGetenv = os.Getenv

// VerifyRequired reports whether fail-closed signature verification is demanded
// when installing. It is **on by default** (secure by default): only an explicit
// PKGX_VERIFY=0/false/no/off opts out. Anything else — unset, 1/true/yes/on, or
// an unrecognised value — keeps verification on.
func VerifyRequired() bool {
	switch strings.ToLower(strings.TrimSpace(osGetenv("PKGX_VERIFY"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// SigningPublicKey is the go-pkgx bottle signing key (minisign format). A signed
// bottle carries a cosign-style signature referrer whose signature verifies
// against this key; verification is fail-closed. It is a var (not const) only so
// tests can substitute a throwaway key.
var SigningPublicKey = "RWQ+rmH+fXy2iYr+gReQAOQtYWtH0A7UlxcAa2hpr+txNBwGqtpFsR6L"

// Signature referrer conventions.
const (
	// ArtifactTypeSignature marks a cosign signature referrer manifest.
	ArtifactTypeSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// MediaSimpleSigning is the media type of the simple-signing payload blob.
	MediaSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	// CosignSignatureAnnotation carries the base64 signature on the referrer
	// manifest (cosign's convention).
	CosignSignatureAnnotation = "dev.cosignproject.cosign/signature"
)

// VerifySignature checks a cosign simple-signing signature over a bottle
// tarball: the base64 sig must verify over payload against pubkey (defaulting to
// the pinned SigningPublicKey), and payload must commit to this exact tarball
// (docker-manifest-digest == sha256(tarball)). Every failure returns an error —
// callers treat that as fail-closed.
func VerifySignature(tarball, payload []byte, b64sig, pubkey string) error {
	if pubkey == "" {
		pubkey = SigningPublicKey
	}
	_, pub, err := sign.ParsePublicKey(pubkey)
	if err != nil {
		return err
	}
	if err := sign.VerifyBlob(payload, b64sig, pub); err != nil {
		return err
	}
	var p struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("bottle: bad signing payload: %w", err)
	}
	sum := sha256.Sum256(tarball)
	if want := "sha256:" + hex.EncodeToString(sum[:]); p.Critical.Image.Digest != want {
		return errors.New("bottle: signature does not match this bottle")
	}
	return nil
}
