package bottle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-attest/sign"
)

// VerifyRequired reports whether fail-closed signature verification is demanded
// when installing. It is **on by default** (secure by default): only an explicit
// ZPKG_VERIFY=0/false/no/off opts out. Anything else — unset, 1/true/yes/on, or
// an unrecognised value — keeps verification on. The value is read through Env,
// so it may come from a real environment variable or from ~/.zpkg/config.hcl2.
func VerifyRequired() bool {
	switch strings.ToLower(strings.TrimSpace(Env("ZPKG_VERIFY"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// SigningPublicKey is the go-zpkg bottle signing key (minisign format). A signed
// bottle carries a cosign-style signature referrer whose signature verifies
// against this key; verification is fail-closed. It is a var (not const) only so
// tests can substitute a throwaway key.
//
// ⛔ IT IS THE DEFAULT TRUST SET, NOT THE WHOLE OF IT. What a client will
// accept is a TrustSet — this key unless the operator says otherwise, plus
// whatever ZPKG_EXTRA_TRUSTED_KEYS adds, and a threshold over the lot. See
// trust.go; everything that verifies a bottle goes through LoadTrustSet.
var SigningPublicKey = "RWQ+rmH+fXy2iYr+gReQAOQtYWtH0A7UlxcAa2hpr+txNBwGqtpFsR6L"

// Signature referrer conventions.
const (
	// ArtifactTypeSignature marks a cosign signature referrer manifest.
	ArtifactTypeSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
	// ArtifactTypeProvenance marks the in-toto SLSA provenance referrer: the
	// statement that says WITH WHAT a bottle was built.
	//
	// ⛔ IT IS THE ONLY PLACE THE BUILDER IS RECORDED. The build's identity
	// (Concrete) deliberately excludes the builder — a zbk release must not
	// re-address every bottle in the registry, which is Nix's and Spack's
	// position too. So "which factory made this?" is answerable ONLY from
	// this attestation, and anything that wants to ask has to read it.
	ArtifactTypeProvenance = "application/vnd.in-toto+json"
	// MediaSimpleSigning is the media type of the simple-signing payload blob.
	MediaSimpleSigning = "application/vnd.dev.cosign.simplesigning.v1+json"
	// CosignSignatureAnnotation carries the base64 signature on the referrer
	// manifest (cosign's convention).
	CosignSignatureAnnotation = "dev.cosignproject.cosign/signature"
	// SignerKeyIDAnnotation names, in hex, the minisign key id that made the
	// signature on this referrer.
	//
	// ⛔ IT IS A HINT AND MUST NEVER BE TRUSTED. A cosign blob signature is a
	// bare Ed25519 signature: it does not say which key made it, so with two
	// signers a verifier would have to try every trusted key against every
	// signature. This annotation turns that product back into a walk — and
	// nothing more. Verify tries the hinted key FIRST and then the others, so
	// an annotation that lies costs time and changes no verdict.
	//
	// There is deliberately no annotation for the signer's NAME. A name on the
	// artefact is written by whoever pushed it; the name a user reads comes
	// from their own trust set, which is the only place it means anything.
	SignerKeyIDAnnotation = "org.go-zpkg.signer.keyid"

	// GlibcVersionAnnotation and GlibcMinKernelAnnotation describe a
	// glibc-flavored bottle on its per-platform manifest: the exact glibc it
	// was built against, and (for the glibc bottle itself) glibc's min
	// supported kernel from .note.ABI-tag. A glibc-aware resolver/selector
	// reads these. They live in annotations.go with the rest, and are read
	// through Annotation() so a bottle published under an older spelling is
	// still understood.
)

// VerifySignature checks a cosign simple-signing signature over a bottle
// tarball: the base64 sig must verify over payload against pubkey (defaulting to
// the pinned SigningPublicKey), and payload must commit to this exact tarball
// (docker-manifest-digest == sha256(tarball)). Every failure returns an error —
// callers treat that as fail-closed.
func VerifySignature(tarball, payload []byte, b64sig, pubkey string) error {
	sum := sha256.Sum256(tarball)
	return VerifySignatureDigest("sha256:"+hex.EncodeToString(sum[:]), payload, b64sig, pubkey)
}

// VerifySignatureDigest is VerifySignature for a tarball identified by its
// DIGEST rather than by its bytes. The bytes are only ever hashed here, so a
// caller that streamed the bottle to disk — computing the digest on the way —
// can verify the signature without reading the tarball back, let alone holding
// it in memory.
func VerifySignatureDigest(digest string, payload []byte, b64sig, pubkey string) error {
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
	return payloadCommitsTo(payload, digest)
}

// payloadCommitsTo checks that a simple-signing payload names this exact
// bottle. A valid signature over SOMEBODY ELSE'S payload is the whole attack
// this prevents, so it is kept apart from the key check and both are run on
// every path — TrustSet.Verify reuses it.
func payloadCommitsTo(payload []byte, digest string) error {
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
	if p.Critical.Image.Digest != digest {
		return errors.New("bottle: signature does not match this bottle")
	}
	return nil
}
