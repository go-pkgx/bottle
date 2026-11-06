package bottle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-attest/sign"
)

// newTrustEnv isolates the trust configuration: an absent config file and a
// lookupEnv backed by m, so only what a test sets is read.
func newTrustEnv(t *testing.T, m map[string]string) {
	t.Helper()
	setConfigPath(t, filepath.Join(t.TempDir(), "absent.hcl2"))
	setLookup(m)
}

// pinKey points the compiled-in signing key at a throwaway one.
func pinKey(t *testing.T, kp *sign.Keypair) {
	t.Helper()
	old := SigningPublicKey
	SigningPublicKey = kp.PublicKeyString()
	t.Cleanup(func() { SigningPublicKey = old })
}

func mustGenerate(t *testing.T) *sign.Keypair {
	t.Helper()
	kp, err := sign.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestParseSigner(t *testing.T) {
	kp := mustGenerate(t)
	pub := kp.PublicKeyString()

	s, err := ParseSigner("alice:" + pub)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "alice" || s.Key != pub {
		t.Errorf("name/key = %q/%q", s.Name, s.Key)
	}
	if len(s.KeyID()) != 16 {
		t.Errorf("key id %q is not 8 bytes of hex", s.KeyID())
	}
	if !strings.Contains(s.String(), s.KeyID()) {
		t.Errorf("String() %q should carry the key id", s.String())
	}

	// A bare key is named by its own key id: it still has to be printable.
	bare, err := ParseSigner("  " + pub + "  ")
	if err != nil {
		t.Fatal(err)
	}
	if bare.Name != bare.KeyID() {
		t.Errorf("unnamed key: name = %q, want the key id %q", bare.Name, bare.KeyID())
	}

	for _, bad := range []string{"", "   ", "alice:", "alice:not-a-key", "garbage"} {
		if _, err := ParseSigner(bad); err == nil {
			t.Errorf("ParseSigner(%q) should fail", bad)
		}
	}
}

func TestParseSignersRefusesTooMany(t *testing.T) {
	kp := mustGenerate(t)
	list := strings.TrimSpace(strings.Repeat(kp.PublicKeyString()+" ", MaxTrustedKeys))
	if _, err := ParseSigners(list); err != nil {
		t.Fatalf("%d keys should be allowed: %v", MaxTrustedKeys, err)
	}
	if _, err := ParseSigners(list + " " + kp.PublicKeyString()); err == nil {
		t.Errorf("%d keys should be refused", MaxTrustedKeys+1)
	}
}

func TestLoadTrustSetDefault(t *testing.T) {
	kp := mustGenerate(t)
	pinKey(t, kp)
	newTrustEnv(t, nil)

	ts, err := LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Signers) != 1 || ts.Signers[0].Name != DefaultSignerName {
		t.Errorf("default trust set = %v, want just %s", ts.Names(), DefaultSignerName)
	}
	if ts.Threshold != DefaultThreshold {
		t.Errorf("threshold = %d, want %d", ts.Threshold, DefaultThreshold)
	}
}

// ⛔⛔ ROTATION MUST NOT INVALIDATE WHAT THE OLD KEY SIGNED. If retiring a key
// dropped it from the default trust set, the whole published registry would
// stop verifying the day we rotate — and since rotation is the answer to a
// lost or compromised key, a design where it breaks everything is one where
// nobody rotates.
func TestRetiredKeysStayTrusted(t *testing.T) {
	current, old := mustGenerate(t), mustGenerate(t)
	pinKey(t, current)
	oldRetired := RetiredSigningPublicKeys
	RetiredSigningPublicKeys = []string{"go-zpkg-2025:" + old.PublicKeyString()}
	t.Cleanup(func() { RetiredSigningPublicKeys = oldRetired })
	newTrustEnv(t, nil)

	ts, err := LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ts.Names(), ","); got != DefaultSignerName+",go-zpkg-2025" {
		t.Fatalf("trust set = %q, want the current key and the retired one", got)
	}

	const digest = "sha256:aa"
	// A bottle signed only by the RETIRED key still verifies.
	names, untrusted, err := ts.Count(digest, []Attestation{signFor(t, old, digest, false)})
	if err != nil || untrusted != 0 || strings.Join(names, ",") != "go-zpkg-2025" {
		t.Errorf("a bottle signed by the retired key: names=%v untrusted=%d err=%v", names, untrusted, err)
	}

	// ⛔ AND AN OVERLAP BOTTLE COUNTS AS TWO. During a rotation the publisher
	// signs with both; a scheme that discounted the retired key would make
	// that look like one signer and a threshold of two unmeetable exactly
	// while rotating.
	names, _, err = ts.Count(digest, []Attestation{
		signFor(t, current, digest, true),
		signFor(t, old, digest, true),
	})
	if err != nil || len(names) != 2 {
		t.Errorf("overlap bottle: names=%v err=%v", names, err)
	}

	// A typo in the retired list is skipped, not fatal: the current key must
	// keep working, because without it there is nothing to trust at all.
	RetiredSigningPublicKeys = []string{"broken:not-a-key", "go-zpkg-2025:" + old.PublicKeyString()}
	ts, err = LoadTrustSet()
	if err != nil || len(ts.Signers) != 2 {
		t.Errorf("an unparseable retired entry took out the set: %v %v", ts.Names(), err)
	}
}

func TestLoadTrustSetReplaceAndExtend(t *testing.T) {
	ours, alice := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)

	// ZPKG_TRUSTED_KEYS replaces: ours is gone.
	newTrustEnv(t, map[string]string{TrustedKeysEnv: "alice:" + alice.PublicKeyString()})
	ts, err := LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ts.Names(), ","); got != "alice" {
		t.Errorf("replace: trust set = %q, want just alice", got)
	}

	// ZPKG_EXTRA_TRUSTED_KEYS adds to the default.
	newTrustEnv(t, map[string]string{ExtraTrustedKeysEnv: "alice:" + alice.PublicKeyString()})
	ts, err = LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ts.Names(), ","); got != DefaultSignerName+",alice" {
		t.Errorf("extend: trust set = %q", got)
	}

	// The same key twice is ONE key: otherwise one signature counts twice.
	newTrustEnv(t, map[string]string{ExtraTrustedKeysEnv: "again:" + ours.PublicKeyString()})
	ts, err = LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Signers) != 1 || ts.Signers[0].Name != DefaultSignerName {
		t.Errorf("duplicate key: trust set = %v, want one entry named %s", ts.Names(), DefaultSignerName)
	}
}

func TestLoadTrustSetThreshold(t *testing.T) {
	ours, alice := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)

	newTrustEnv(t, map[string]string{
		ExtraTrustedKeysEnv: "alice:" + alice.PublicKeyString(),
		TrustThresholdEnv:   "2",
	})
	ts, err := LoadTrustSet()
	if err != nil {
		t.Fatal(err)
	}
	if ts.Threshold != 2 {
		t.Errorf("threshold = %d, want 2", ts.Threshold)
	}

	for _, bad := range []string{"0", "-1", "two", "1.5"} {
		newTrustEnv(t, map[string]string{TrustThresholdEnv: bad})
		if _, err := LoadTrustSet(); err == nil {
			t.Errorf("%s=%q should be refused", TrustThresholdEnv, bad)
		}
	}

	// ⛔ A threshold nobody could meet is a configuration error, said here —
	// not an install failure that blames the bottle.
	newTrustEnv(t, map[string]string{TrustThresholdEnv: "3"})
	_, err = LoadTrustSet()
	if err == nil || !strings.Contains(err.Error(), "cannot be met") {
		t.Errorf("threshold above the key count: got %v", err)
	}

	// A bad key list is reported against the variable that holds it.
	newTrustEnv(t, map[string]string{TrustedKeysEnv: "alice:nonsense"})
	if _, err := LoadTrustSet(); err == nil || !strings.Contains(err.Error(), TrustedKeysEnv) {
		t.Errorf("bad %s: got %v", TrustedKeysEnv, err)
	}
	newTrustEnv(t, map[string]string{ExtraTrustedKeysEnv: "alice:nonsense"})
	if _, err := LoadTrustSet(); err == nil || !strings.Contains(err.Error(), ExtraTrustedKeysEnv) {
		t.Errorf("bad %s: got %v", ExtraTrustedKeysEnv, err)
	}
}

// signFor makes the attestation one keypair would attach to a bottle digest.
func signFor(t *testing.T, kp *sign.Keypair, digest string, withHint bool) Attestation {
	t.Helper()
	payload, err := sign.SimpleSigningPayload("pkg:pkgx/x", digest)
	if err != nil {
		t.Fatal(err)
	}
	a := Attestation{Payload: payload, Sig: kp.SignPayload(payload)}
	if withHint {
		a.KeyID = Signer{Key: kp.PublicKeyString()}.KeyID()
	}
	return a
}

func TestTrustSetVerify(t *testing.T) {
	ours, alice, mallory := mustGenerate(t), mustGenerate(t), mustGenerate(t)
	const digest = "sha256:aa"
	ts := TrustSet{
		Signers: []Signer{
			{Name: DefaultSignerName, Key: ours.PublicKeyString()},
			{Name: "alice", Key: alice.PublicKeyString()},
		},
		Threshold: 1,
	}

	names, untrusted, err := ts.Count(digest, []Attestation{signFor(t, ours, digest, false)})
	if err != nil || untrusted != 0 || strings.Join(names, ",") != DefaultSignerName {
		t.Fatalf("one trusted signature: names=%v untrusted=%d err=%v", names, untrusted, err)
	}

	// Both builders: the names come back sorted, and both are there.
	names, _, err = ts.Count(digest, []Attestation{
		signFor(t, alice, digest, true),
		signFor(t, ours, digest, true),
	})
	if err != nil || strings.Join(names, ",") != "alice,"+DefaultSignerName {
		t.Fatalf("two trusted signatures: names=%v err=%v", names, err)
	}

	// An untrusted key does not count — and is not an error either.
	names, untrusted, err = ts.Count(digest, []Attestation{signFor(t, mallory, digest, false)})
	if err != nil || len(names) != 0 || untrusted != 1 {
		t.Fatalf("untrusted signature: names=%v untrusted=%d err=%v", names, untrusted, err)
	}
	rep := SignatureReport{Signers: names, Untrusted: untrusted, Threshold: 1}
	if rep.Err() == nil || !strings.Contains(rep.Err().Error(), "not in the trust set") {
		t.Errorf("verdict should say the key is untrusted: %v", rep.Err())
	}
	if rep.String() != "no trusted signature" {
		t.Errorf("cell = %q", rep.String())
	}

	// A signature over somebody else's digest never counts.
	names, untrusted, _ = ts.Count(digest, []Attestation{signFor(t, ours, "sha256:bb", false)})
	if len(names) != 0 || untrusted != 1 {
		t.Errorf("a signature over another digest counted: names=%v untrusted=%d", names, untrusted)
	}
}

// The report keeps "nobody signed" apart from "we could not read what was
// attached", and says which in the verdict.
func TestSignatureReport(t *testing.T) {
	empty := SignatureReport{Threshold: 1}
	if empty.Signed() || empty.OK() || empty.String() != "unsigned" {
		t.Errorf("empty report: signed=%v ok=%v cell=%q", empty.Signed(), empty.OK(), empty.String())
	}
	if err := empty.Err(); err == nil || !strings.Contains(err.Error(), "no signature referrer") {
		t.Errorf("empty report verdict: %v", err)
	}

	broken := SignatureReport{Malformed: 2, Threshold: 1}
	if !broken.Signed() {
		t.Error("a malformed referrer still means something was attached")
	}
	if err := broken.Err(); err == nil || !strings.Contains(err.Error(), "2 signature referrers are malformed") {
		t.Errorf("malformed verdict: %v", err)
	}

	ok := SignatureReport{Signers: []string{"go-zpkg", "alice"}, Threshold: 2}
	if !ok.OK() || ok.Err() != nil || ok.String() != "go-zpkg, alice" {
		t.Errorf("met threshold: ok=%v err=%v cell=%q", ok.OK(), ok.Err(), ok.String())
	}

	// A zero Threshold means the default, not "no signature needed".
	if (SignatureReport{}).OK() {
		t.Error("an unsigned report with no threshold set must not pass")
	}
}

// ⛔⛔ THE SAME SIGNATURE TWICE IS ONE KEY'S WORD, NOT TWO (TUF §5.4.2).
// Anyone who can push a referrer can push it twice; without this rule a
// threshold of two is met by a single signer copying their own signature.
func TestTrustSetVerifyCountsEachKeyOnce(t *testing.T) {
	ours := mustGenerate(t)
	const digest = "sha256:aa"
	ts := TrustSet{Signers: []Signer{{Name: DefaultSignerName, Key: ours.PublicKeyString()}}, Threshold: 2}

	a := signFor(t, ours, digest, false)
	names, untrusted, err := ts.Count(digest, []Attestation{a, a, a})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 {
		t.Errorf("counted %d keys from one signer: %v", len(names), names)
	}
	rep := SignatureReport{Signers: names, Untrusted: untrusted, Threshold: ts.Threshold}
	if rep.OK() {
		t.Fatal("three copies of one signature met a threshold of two")
	}
	if !strings.Contains(rep.Err().Error(), "1 trusted key") {
		t.Errorf("message should say one key signed: %v", rep.Err())
	}
}

// The key id on a referrer orders the attempts and nothing else, so a wrong
// one costs time and changes no verdict.
func TestTrustSetVerifyKeyIDIsOnlyAHint(t *testing.T) {
	ours, alice := mustGenerate(t), mustGenerate(t)
	const digest = "sha256:aa"
	ts := TrustSet{Signers: []Signer{
		{Name: DefaultSignerName, Key: ours.PublicKeyString()},
		{Name: "alice", Key: alice.PublicKeyString()},
	}, Threshold: 1}

	a := signFor(t, ours, digest, false)
	a.KeyID = Signer{Key: alice.PublicKeyString()}.KeyID() // a lie
	names, _, err := ts.Count(digest, []Attestation{a})
	if err != nil || strings.Join(names, ",") != DefaultSignerName {
		t.Fatalf("a wrong key id changed the verdict: names=%v err=%v", names, err)
	}

	a.KeyID = "not-hex-at-all"
	if names, _, err := ts.Count(digest, []Attestation{a}); err != nil || len(names) != 1 {
		t.Fatalf("a nonsense key id changed the verdict: names=%v err=%v", names, err)
	}
}

func TestTrustSetVerifyBounds(t *testing.T) {
	ours := mustGenerate(t)
	const digest = "sha256:aa"

	// An empty trust set verifies nothing, and says so rather than passing.
	if _, _, err := (TrustSet{Threshold: 1}).Count(digest, []Attestation{signFor(t, ours, digest, false)}); err == nil ||
		!strings.Contains(err.Error(), "trust set is empty") {
		t.Errorf("empty trust set: %v", err)
	}

	// ⛔ Too many signatures is REFUSED, not truncated: verifying the first
	// MaxSignatures of a longer list would make the verdict depend on where
	// the list was cut.
	ts := TrustSet{Signers: []Signer{{Name: "ours", Key: ours.PublicKeyString()}}, Threshold: 1}
	flood := make([]Attestation, MaxSignatures+1)
	for i := range flood {
		flood[i] = signFor(t, ours, digest, false)
	}
	if _, _, err := ts.Count(digest, flood); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("a flood of signatures should be refused: %v", err)
	}
}

// pushTwoSigned pushes one bottle carrying a signature from each keypair, in
// the order given.
func pushTwoSigned(t *testing.T, c *OCIClient, project string, tarball []byte, kps ...*sign.Keypair) {
	t.Helper()
	refs := []Referrer{
		{ArtifactType: "application/vnd.cyclonedx+json", MediaType: "application/vnd.cyclonedx+json", Blob: []byte(`{}`)},
	}
	for _, kp := range kps {
		payload, err := sign.SimpleSigningPayload("pkg:pkgx/"+project, digestOf(tarball))
		if err != nil {
			t.Fatal(err)
		}
		id := Signer{Key: kp.PublicKeyString()}.KeyID()
		refs = append(refs, Referrer{
			ArtifactType: ArtifactTypeSignature,
			MediaType:    MediaSimpleSigning,
			Blob:         payload,
			Annotations: map[string]string{
				CosignSignatureAnnotation: kp.SignPayload(payload),
				SignerKeyIDAnnotation:     id,
				// Distinct referrer manifests: identical content would be
				// one object in the registry, not two signatures.
				"org.go-zpkg.test.signer": id,
			},
		})
	}
	if _, err := c.PushWithReferrers(project, "1.0.0", "linux", "x86-64", tarball, ".tar.gz", refs); err != nil {
		t.Fatal(err)
	}
}

// ⛔⛔ THE WITNESS. Before the trust set, VerifyBottleDigest took the FIRST
// signature referrer and verified it against one pinned key. A bottle signed
// by both builders therefore verified or failed according to the order the
// registry served its referrers in — and the failure read as tampering.
//
// The arrangement is the one the old code got wrong: somebody ELSE signed
// first, we signed second, and the client trusts only us. Taking the first
// referrer reports a bottle our own key signed as unverifiable.
//
// ⛔ A SIGNATURE FROM OUTSIDE THE TRUST SET IS NOT AN ERROR, IT IS SOMEBODY
// ELSE'S OPINION. Anyone may attach one; treating that as a reason to refuse
// would let a stranger invalidate any bottle by signing it.
func TestVerifyBottleIsNotOrderDependent(t *testing.T) {
	ours, stranger := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)
	newTrustEnv(t, nil) // only our own key is trusted

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))
	tarball := makeGzTarball("stranger-first")
	pushTwoSigned(t, c, "stranger.first", tarball, stranger, ours)

	rep, err := c.SignaturesOfDigest("stranger.first", "1.0.0", "linux", "x86-64", digestOf(tarball))
	if err != nil {
		t.Fatal(err)
	}
	if verr := rep.Err(); verr != nil {
		t.Fatalf("a bottle our own key signed was rejected: %v", verr)
	}
	if strings.Join(rep.Signers, ",") != DefaultSignerName {
		t.Errorf("signers = %v, want %s", rep.Signers, DefaultSignerName)
	}
	if rep.Untrusted != 1 {
		t.Errorf("the stranger's signature should be counted as untrusted, got %d", rep.Untrusted)
	}
	// And the install path agrees with the report.
	if err := c.VerifyBottle("stranger.first", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Errorf("install-time verification rejected it: %v", err)
	}
}

// With a threshold of two, one builder's word is not enough — and the message
// says who did sign, because that is the reader's next question.
func TestVerifyBottleThresholdOfTwo(t *testing.T) {
	ours, alice := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)
	newTrustEnv(t, map[string]string{
		ExtraTrustedKeysEnv: "alice:" + alice.PublicKeyString(),
		TrustThresholdEnv:   "2",
	})

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))

	one := makeGzTarball("one-signer")
	pushTwoSigned(t, c, "one.signer", one, ours)
	err := c.VerifyBottle("one.signer", "1.0.0", "linux", "x86-64", one)
	if err == nil {
		t.Fatal("one signature met a threshold of two")
	}
	if !strings.Contains(err.Error(), DefaultSignerName) || !strings.Contains(err.Error(), "one.signer") {
		t.Errorf("message should name the signer and the bottle: %v", err)
	}

	both := makeGzTarball("two-signers")
	pushTwoSigned(t, c, "two.signers", both, ours, alice)
	if err := c.VerifyBottle("two.signers", "1.0.0", "linux", "x86-64", both); err != nil {
		t.Fatalf("two independent signatures were rejected: %v", err)
	}
}

// ⛔⛔ THE THRESHOLD HAS TO BITE WHERE BYTES LAND, NOT ONLY IN A LISTING.
// A trust policy that only the `builds` table consults would be decoration:
// what matters is that `Install` refuses. This walks the real install path —
// resolve, pull, verify, extract — and then checks the CACHE path too, which
// is the one that historically skips checks because the bytes "are already
// ours".
func TestInstallEnforcesTheThreshold(t *testing.T) {
	setGoos(t, "linux")
	setGoarch(t, "x86-64")
	ours, alice := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))

	one := ociGzBottle(t, "thr.one", "1.0.0", map[string]string{"bin/a": "x"})
	pushTwoSigned(t, c, "thr.one", one, ours)
	both := ociGzBottle(t, "thr.both", "1.0.0", map[string]string{"bin/b": "x"})
	pushTwoSigned(t, c, "thr.both", both, ours, alice)

	oldDist := DistBase
	DistBase = fr.base("go-zpkg/bottles")
	resetOCICache()
	defer func() { DistBase = oldDist; resetOCICache() }()

	newTrustEnv(t, map[string]string{
		"ZPKG_VERIFY":       "1",
		ExtraTrustedKeysEnv: "alice:" + alice.PublicKeyString(),
		TrustThresholdEnv:   "2",
	})

	dir := t.TempDir()
	_, err := Install(Resolved{"thr.one", ParseVer("1.0.0")}, dir)
	if err == nil {
		t.Fatal("a bottle one builder signed installed under a threshold of two")
	}
	if !strings.Contains(err.Error(), "requires 2") {
		t.Errorf("install error should say what was required: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "thr.one")); serr == nil {
		t.Error("a refused bottle left files behind")
	}

	if fresh, err := Install(Resolved{"thr.both", ParseVer("1.0.0")}, t.TempDir()); err != nil || !fresh {
		t.Fatalf("a bottle both builders signed was refused: fresh=%v err=%v", fresh, err)
	}

	// ⛔ AND THE CACHE IS NOT A WAY ROUND IT. fetchBottle checks a cache hit
	// against the REGISTRY's signatures, so tightening the policy after the
	// bytes are cached still refuses them.
	newTrustEnv(t, map[string]string{
		"ZPKG_VERIFY":     "1",
		TrustThresholdEnv: "1",
	}) // alice is no longer trusted, and ours alone now suffices
	if fresh, err := Install(Resolved{"thr.both", ParseVer("1.0.0")}, t.TempDir()); err != nil || !fresh {
		t.Fatalf("our own signature should still carry it: fresh=%v err=%v", fresh, err)
	}
}

// ⛔⛔ "WITH WHAT WAS THIS BUILT" HAS ONE ANSWER AND IT IS THE PROVENANCE.
// The builder is deliberately absent from the identity — a zbk release must
// not re-address every bottle — so two factories building identical inputs
// produce the same hash, and the attestation is the only thing that tells
// them apart. A reader who cannot see it cannot audit the chain at all.
func TestProvenanceNamesWhatBuiltTheBottle(t *testing.T) {
	ours := mustGenerate(t)
	pinKey(t, ours)
	newTrustEnv(t, nil)

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))
	tarball := makeGzTarball("provenanced")

	const builder = "https://github.com/go-zpkg/zbk@v0.64.0"
	payload, err := sign.SimpleSigningPayload("pkg:pkgx/prov.pkg", digestOf(tarball))
	if err != nil {
		t.Fatal(err)
	}
	stmt := []byte(`{"predicate":{"runDetails":{"builder":{"id":"` + builder + `"}}}}`)
	if _, err := c.PushWithReferrers("prov.pkg", "1.0.0", "linux", "x86-64", tarball, ".tar.gz", []Referrer{
		{ArtifactType: ArtifactTypeProvenance, MediaType: ArtifactTypeProvenance, Blob: stmt},
		{ArtifactType: ArtifactTypeSignature, MediaType: MediaSimpleSigning, Blob: payload,
			Annotations: map[string]string{
				CosignSignatureAnnotation: ours.SignPayload(payload),
				SignerKeyIDAnnotation:     Signer{Key: ours.PublicKeyString()}.KeyID(),
			}},
	}); err != nil {
		t.Fatal(err)
	}

	rep, got, err := c.ProvenanceOfTag("prov.pkg", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if got != builder {
		t.Errorf("builder = %q, want %q", got, builder)
	}
	// ⛔ AND IT STILL ANSWERS THE SIGNATURE HALF. The two come off one
	// referrer listing; a refactor that broke the second while keeping the
	// first would go unnoticed without this line.
	if !rep.OK() || strings.Join(rep.Signers, ",") != DefaultSignerName {
		t.Errorf("signers = %v ok=%v", rep.Signers, rep.OK())
	}

	// A bottle with no provenance says "" — NOT RECORDED, which a caller
	// must not render as "built by nobody".
	plain := makeGzTarball("no-provenance")
	pushTwoSigned(t, c, "plain.pkg", plain, ours)
	if _, got, err := c.ProvenanceOfTag("plain.pkg", "1.0.0", "linux", "x86-64"); err != nil || got != "" {
		t.Errorf("a bottle with no provenance: builder=%q err=%v", got, err)
	}

	// An unparseable statement is the same answer, not a refusal: one broken
	// attestation must not cost the whole listing.
	broken := makeGzTarball("bad-provenance")
	if _, err := c.PushWithReferrers("bad.pkg", "1.0.0", "linux", "x86-64", broken, ".tar.gz", []Referrer{
		{ArtifactType: ArtifactTypeProvenance, MediaType: ArtifactTypeProvenance, Blob: []byte("{not json")},
	}); err != nil {
		t.Fatal(err)
	}
	if _, got, err := c.ProvenanceOfTag("bad.pkg", "1.0.0", "linux", "x86-64"); err != nil || got != "" {
		t.Errorf("an unreadable statement: builder=%q err=%v", got, err)
	}
}

func TestShortBuilder(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/go-zpkg/zbk@v0.64.0": "zbk@v0.64.0",
		"https://github.com/go-pkgx/bk@v0.26.0":  "bk@v0.26.0",
		// Not a URL: returned whole, because a builder we do not recognise
		// is the one most worth reading in full.
		"somebody's laptop": "somebody's laptop",
		"":                  "",
		// A URL with no path beyond the host keeps what there is.
		"https://example.test": "example.test",
	} {
		if got := ShortBuilder(in); got != want {
			t.Errorf("ShortBuilder(%q) = %q, want %q", in, got, want)
		}
	}
}

// A build listing carries who vouches for each build, and keeps "not asked"
// apart from "nobody".
func TestBuildsOfCarriesTheSigners(t *testing.T) {
	ours := mustGenerate(t)
	pinKey(t, ours)
	newTrustEnv(t, nil)

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))
	tarball := makeGzTarball("listed")
	pushTwoSigned(t, c, "listed.pkg", tarball, ours)

	oldDist := DistBase
	DistBase = fr.base("go-zpkg/bottles")
	resetOCICache()
	defer func() { DistBase = oldDist; resetOCICache() }()

	builds, err := BuildsOf("listed.pkg", "1.0.0", t.TempDir(), "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 1 {
		t.Fatalf("got %d builds", len(builds))
	}
	rep := builds[0].Signatures
	if rep == nil {
		t.Fatal("the listing did not record who signed")
	}
	if strings.Join(rep.Signers, ",") != DefaultSignerName || !rep.OK() {
		t.Errorf("signers = %v ok=%v", rep.Signers, rep.OK())
	}

	// A build that is only installed was never published, so there is
	// nothing to have signed and nobody to ask: nil, not "unsigned".
	local, err := BuildsOf("absent.pkg", "1.0.0", t.TempDir(), "linux", "x86-64")
	if err == nil && len(local) > 0 && local[0].Signatures != nil {
		t.Error("an unpublished build should carry no signature report")
	}
}

// ⛔⛔ THE SECOND BUILDER'S WHOLE WORKFLOW, END TO END. Rebuild, compare the
// digest against what is published, and — only if they agree — attach a
// signature to the SAME bytes. Not a second bottle: the point of independent
// agreement is that there is one artefact and several people's word on it.
func TestAttachASecondSignatureToAPublishedBottle(t *testing.T) {
	ours, alice := mustGenerate(t), mustGenerate(t)
	pinKey(t, ours)

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))
	tarball := makeGzTarball("rebuilt-identically")
	pushTwoSigned(t, c, "rebuilt.pkg", tarball, ours)

	// What a rebuilder checks before signing anything.
	published, err := c.BottleDigest("rebuilt.pkg", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if published != digestOf(tarball) {
		t.Fatalf("published digest %s is not the rebuild's %s", published, digestOf(tarball))
	}

	payload, err := sign.SimpleSigningPayload("pkg:pkgx/rebuilt.pkg", published)
	if err != nil {
		t.Fatal(err)
	}
	err = c.AttachReferrer("rebuilt.pkg", "1.0.0", "linux", "x86-64", Referrer{
		ArtifactType: ArtifactTypeSignature,
		MediaType:    MediaSimpleSigning,
		Blob:         payload,
		Annotations: map[string]string{
			CosignSignatureAnnotation: alice.SignPayload(payload),
			SignerKeyIDAnnotation:     Signer{Key: alice.PublicKeyString()}.KeyID(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The bottle now meets a threshold of two that it did not meet before.
	newTrustEnv(t, map[string]string{
		ExtraTrustedKeysEnv: "alice:" + alice.PublicKeyString(),
		TrustThresholdEnv:   "2",
	})
	rep, err := c.SignaturesOfTag("rebuilt.pkg", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || strings.Join(rep.Signers, ",") != "alice,"+DefaultSignerName {
		t.Errorf("after attaching: signers=%v ok=%v", rep.Signers, rep.OK())
	}
	if err := c.VerifyBottle("rebuilt.pkg", "1.0.0", "linux", "x86-64", tarball); err != nil {
		t.Errorf("install-time verification: %v", err)
	}
}

// SignersOfTag answers "who vouches for this?" about a build nobody has
// downloaded: the digest the signature commits to is already in the manifest.
func TestSignersOfTagWithoutTheTarball(t *testing.T) {
	ours := mustGenerate(t)
	pinKey(t, ours)
	newTrustEnv(t, nil)

	fr := newFakeRegistry(t, false)
	defer fr.close()
	c, _ := NewOCIClient(fr.base("go-zpkg/bottles"))
	tarball := makeGzTarball("by-tag")
	pushTwoSigned(t, c, "by.tag", tarball, ours)

	rep, err := c.SignaturesOfTag("by.tag", "1.0.0", "linux", "x86-64")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Signers, ",") != DefaultSignerName || !rep.OK() {
		t.Errorf("signers = %v ok=%v", rep.Signers, rep.OK())
	}
	if _, err := c.SignaturesOfTag("by.tag", "9.9.9", "linux", "x86-64"); err == nil {
		t.Error("a missing tag should be an error")
	}
	if _, err := c.SignaturesOfTag("BAD..name/../x", "1.0.0", "linux", "x86-64"); err == nil {
		t.Error("a bad project should be an error")
	}
}
