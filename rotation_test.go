package dkim

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

var errTransientSign = errors.New("dkim-test: transient signing failure")

// withDNSRecord registers a TXT record for recordName during the test and
// returns a restore function the caller must defer.
func withDNSRecord(recordName, txt string) func() {
	prev := queryMethods[QueryMethodDNSTXT]
	queryMethods[QueryMethodDNSTXT] = func(domain, selector string) (*queryResult, error) {
		if selector+"._domainkey."+domain == recordName {
			return parsePublicKey(txt)
		}
		return prev(domain, selector)
	}
	return func() { queryMethods[QueryMethodDNSTXT] = prev }
}

func publicKeyTXT(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := marshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; p=" + base64Encode(der)
}

// flakySigner fails its first Sign calls, then delegates to the wrapped
// signer. It records every signing attempt.
type flakySigner struct {
	crypto.Signer
	failuresLeft int
	calls        int
}

func (f *flakySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.calls++
	if f.failuresLeft > 0 {
		f.failuresLeft--
		return nil, errTransientSign
	}
	return f.Signer.Sign(rand, digest, opts)
}

// alwaysFailSigner never produces a signature.
type alwaysFailSigner struct {
	crypto.Signer
}

func (f *alwaysFailSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errTransientSign
}

func TestKeyRing_RotationPinsGeneration(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	ring := NewKeyRing()
	g1, err := ring.Add("sel-old", key1)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := ring.Rotate("sel-new", key2)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Generation != 0 || g2.Generation != 1 || ring.Len() != 2 {
		t.Fatalf("unexpected generations: %v %v len=%v", g1.Generation, g2.Generation, ring.Len())
	}

	// Snapshot before another rotation: it must stay on generation 0.
	snap, err := ring.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate("sel-even-newer", key2); err != nil {
		t.Fatal(err)
	}
	if snap.Generation() != 0 || snap.Selector() != "sel-old" {
		t.Fatalf("snapshot drifted to generation %v selector %q", snap.Generation(), snap.Selector())
	}
	if snap.Signer() != crypto.Signer(key1) {
		t.Fatal("snapshot must keep the original private key after rotation")
	}

	fp1, _ := g1.Fingerprint()
	fpSnap, _ := snap.Fingerprint()
	if fp1 != fpSnap {
		t.Fatalf("fingerprint mismatch: %q vs %q", fp1, fpSnap)
	}
	if cur := ring.Current(); cur.Generation != 2 || cur.Selector != "sel-even-newer" {
		t.Fatalf("unexpected current generation: %+v", cur)
	}
}

func TestSign_RetryKeepsSameGeneration(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	ring := NewKeyRing()
	if _, err := ring.Add("brisbane", oldKey); err != nil {
		t.Fatal(err)
	}
	flaky := &flakySigner{Signer: oldKey, failuresLeft: 2}

	// Pin a key snapshot, then rotate the ring before the message is signed.
	snap, err := NewSigningKey("brisbane", flaky)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate("test", newKey); err != nil {
		t.Fatal(err)
	}

	defer withDNSRecord("brisbane._domainkey.example.org", publicKeyTXT(t, &oldKey.PublicKey))()

	report := &SignReport{}
	opts := &SignOptions{
		Domain:     "example.org",
		Key:        snap,
		MaxRetries: 2,
		Report:     report,
	}

	var b bytes.Buffer
	if err := Sign(&b, strings.NewReader(mailString), opts); err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if flaky.calls != 3 {
		t.Fatalf("expected 3 signing attempts, got %v", flaky.calls)
	}
	if snap.Signer() != crypto.Signer(flaky) {
		t.Fatal("pinned snapshot must not be replaced by a rotated key")
	}
	if report.Attempts != 3 {
		t.Errorf("expected report attempts 3, got %v", report.Attempts)
	}
	if report.KeyGeneration != snap.Generation() {
		t.Errorf("report generation %v differs from pinned generation %v",
			report.KeyGeneration, snap.Generation())
	}

	// Report retains selector, key fingerprint and both digests.
	if report.Selector != "brisbane" {
		t.Errorf("expected selector brisbane, got %q", report.Selector)
	}
	fp, _ := PublicKeyFingerprint(&oldKey.PublicKey)
	if report.KeyFingerprint != fp {
		t.Errorf("expected fingerprint %q, got %q", fp, report.KeyFingerprint)
	}
	if report.BodyDigest == "" || report.HeaderDigest == "" {
		t.Errorf("report missing digests: %+v", report)
	}
	if report.Stage != SigningStageFormat {
		t.Errorf("expected final stage %q, got %q", SigningStageFormat, report.Stage)
	}

	// The signature must verify against the old generation's DNS record.
	verifs, err := VerifyWithOptions(&b, &VerifyOptions{Reports: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifs) != 1 || verifs[0].Err != nil {
		t.Fatalf("expected one valid verification, got %+v", verifs)
	}
	v := verifs[0]
	if v.Selector != "brisbane" {
		t.Errorf("expected verification selector brisbane, got %q", v.Selector)
	}
	if v.Report == nil || v.Report.KeyFingerprint != fp {
		t.Errorf("verification report fingerprint mismatch: %+v", v.Report)
	}
	if v.Report.BodyDigest != report.BodyDigest || v.Report.HeaderDigest != report.HeaderDigest {
		t.Errorf("verification digests don't match signing report: sign=%+v verify=%+v",
			report, v.Report)
	}
}

func TestSign_RetryExhaustedReportsFailingStage(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := NewSigningKey("brisbane", &alwaysFailSigner{Signer: oldKey})
	if err != nil {
		t.Fatal(err)
	}

	report := &SignReport{}
	var b bytes.Buffer
	err = Sign(&b, strings.NewReader(mailString), &SignOptions{
		Domain:     "example.org",
		Key:        snap,
		MaxRetries: 1,
		Report:     report,
	})
	if err == nil {
		t.Fatal("expected signing to fail")
	}
	if report.Stage != SigningStageCryptoSign {
		t.Errorf("expected failing stage %q, got %q", SigningStageCryptoSign, report.Stage)
	}
	if ErrorStage(report.Err) != string(SigningStageCryptoSign) {
		t.Errorf("expected error stage %q, got %q", SigningStageCryptoSign, ErrorStage(report.Err))
	}
	if report.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %v", report.Attempts)
	}
	if report.BodyDigest == "" || report.HeaderDigest == "" {
		t.Errorf("report should retain digests even on failure: %+v", report)
	}
}

func TestVerify_ReportPointsAtFailingStage(t *testing.T) {
	// A message whose body was altered: the "bh=" check must fail and the
	// report must point at the body-hash stage.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer withDNSRecord("brisbane._domainkey.example.org", publicKeyTXT(t, &key.PublicKey))()

	var b bytes.Buffer
	if err := Sign(&b, strings.NewReader(mailString), &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   key,
	}); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(b.Bytes(), []byte("Joe."), []byte("Jane."), 1)

	verifs, err := VerifyWithOptions(bytes.NewReader(tampered), &VerifyOptions{Reports: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifs) != 1 {
		t.Fatalf("expected one verification, got %v", len(verifs))
	}
	v := verifs[0]
	if v.Err == nil {
		t.Fatal("expected verification to fail for tampered body")
	}
	if v.Report == nil {
		t.Fatal("expected a verification report")
	}
	if v.Report.Stage != VerificationStageBodyHash {
		t.Errorf("expected stage %q, got %q", VerificationStageBodyHash, v.Report.Stage)
	}
	if ErrorStage(v.Report.Err) != string(VerificationStageBodyHash) {
		t.Errorf("expected error stage %q, got %q", VerificationStageBodyHash, ErrorStage(v.Report.Err))
	}
	if v.Report.Selector != "brisbane" || v.Report.KeyFingerprint == "" ||
		v.Report.BodyDigest == "" || v.Report.HeaderDigest == "" {
		t.Errorf("report missing required fields: %+v", v.Report)
	}
}

func TestVerify_RotatedKeyMismatchFailsAtCryptoVerify(t *testing.T) {
	// Sign with key1 published at "brisbane", then the DNS record is replaced
	// by key2's generation: verification must fail at the crypto-verify stage,
	// and the report must name the signature's selector and queried key.
	key1, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	if err := Sign(&b, strings.NewReader(mailString), &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   key1,
	}); err != nil {
		t.Fatal(err)
	}

	// Rotation: the old selector now serves the new key.
	defer withDNSRecord("brisbane._domainkey.example.org", publicKeyTXT(t, &key2.PublicKey))()

	verifs, err := VerifyWithOptions(&b, &VerifyOptions{Reports: true})
	if err != nil {
		t.Fatal(err)
	}
	v := verifs[0]
	if v.Err == nil {
		t.Fatal("expected verification to fail after key rotation")
	}
	if ErrorStage(v.Report.Err) != string(VerificationStageCryptoVerify) {
		t.Errorf("expected stage %q, got %q (err=%v)",
			VerificationStageCryptoVerify, ErrorStage(v.Report.Err), v.Err)
	}
	if v.Report.Selector != "brisbane" {
		t.Errorf("expected report selector brisbane, got %q", v.Report.Selector)
	}
	fp2, _ := PublicKeyFingerprint(&key2.PublicKey)
	if v.Report.KeyFingerprint != fp2 {
		t.Errorf("report must fingerprint the queried key")
	}
}

func TestVerify_WithoutReportsStaysNil(t *testing.T) {
	verifs, err := Verify(newMailStringReader(verifiedMailString))
	if err != nil {
		t.Fatal(err)
	}
	if verifs[0].Report != nil {
		t.Error("plain Verify must not attach a report")
	}
}

func TestNewSigningKey_RejectsInvalidMaterial(t *testing.T) {
	if _, err := NewSigningKey("", testPrivateKey); err == nil {
		t.Error("expected an error for an empty selector")
	}
	if _, err := NewSigningKey("brisbane", nil); err == nil {
		t.Error("expected an error for a nil signer")
	}
}

// unsupportedSigner carries a public key type the DKIM package can't
// fingerprint, exercising the options-stage failure path.
type unsupportedSigner struct{}

func (unsupportedSigner) Public() crypto.PublicKey                          { return "not-a-key" }
func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestNewSigner_UnsupportedKeyFailsAtOptionsStage(t *testing.T) {
	snap, err := NewSigningKey("brisbane", unsupportedSigner{})
	if err != nil {
		t.Fatal(err)
	}
	report := &SignReport{}
	_, err = NewSigner(&SignOptions{
		Domain: "example.org",
		Key:    snap,
		Report: report,
	})
	if err == nil {
		t.Fatal("expected an error for an unsupported key type")
	}
	if report.Stage != SigningStageOptions {
		t.Errorf("expected options stage, got %q", report.Stage)
	}
	if report.Selector != "brisbane" {
		t.Errorf("report should still carry the selector, got %q", report.Selector)
	}
}

func TestKeyRing_EmptySnapshotAndUnknownGeneration(t *testing.T) {
	ring := NewKeyRing()
	if _, err := ring.Snapshot(); err == nil {
		t.Error("expected an error when snapshotting an empty ring")
	}
	if _, err := ring.SnapshotGeneration(7); err == nil {
		t.Error("expected an error for an unknown generation")
	}
}

func TestPublicKeyFingerprint_StableAndAlgorithms(t *testing.T) {
	rsaFP, err := PublicKeyFingerprint(&testPrivateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsaFP) != 64 {
		t.Fatalf("expected 64 hex chars, got %v", len(rsaFP))
	}
	if again, _ := PublicKeyFingerprint(&testPrivateKey.PublicKey); again != rsaFP {
		t.Fatal("fingerprint must be stable for the same key")
	}

	edPub := testEd25519PrivateKey.Public().(ed25519.PublicKey)
	edFP, err := PublicKeyFingerprint(edPub)
	if err != nil {
		t.Fatalf("ed25519 fingerprint failed: %v", err)
	}
	if edFP == rsaFP {
		t.Fatal("different key algorithms must have different fingerprints")
	}

	key, err := NewSigningKey("brisbane", testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := key.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if fp != rsaFP {
		t.Fatalf("snapshot fingerprint %q differs from key fingerprint %q", fp, rsaFP)
	}
}

func TestSign_FailureTypesArePreserved(t *testing.T) {
	// A signed message whose signature is corrupted must remain a failError,
	// even though the report records the crypto-verify stage.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer withDNSRecord("brisbane._domainkey.example.org", publicKeyTXT(t, &key.PublicKey))()

	var b bytes.Buffer
	if err := Sign(&b, strings.NewReader(mailString), &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   key,
	}); err != nil {
		t.Fatal(err)
	}

	// Flip a character inside the "b=" tag while leaving "bh=" and the
	// base64 length/alphabet untouched, so parsing succeeds and the failure is
	// raised by the public-key operation at the crypto-verify stage.
	corrupted := corruptSignature(b.Bytes())
	verifs, err := VerifyWithOptions(bytes.NewReader(corrupted), &VerifyOptions{Reports: true})
	if err != nil {
		t.Fatal(err)
	}
	v := verifs[0]
	if v.Err == nil {
		t.Fatal("expected corrupted signature to fail verification")
	}
	if !isFail(v.Err) {
		t.Errorf("expected failError to be preserved, got %T: %v", v.Err, v.Err)
	}
	if ErrorStage(v.Report.Err) != string(VerificationStageCryptoVerify) {
		t.Errorf("expected crypto-verify stage, got %q", ErrorStage(v.Report.Err))
	}
}

// corruptSignature flips the first base64 character of the DKIM "b=" tag.
func corruptSignature(msg []byte) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	idx := bytes.Index(out, []byte("b="))
	if idx < 0 {
		return out
	}
	for i := idx + 2; i < len(out); i++ {
		switch out[i] {
		case 'A':
			out[i] = 'B'
			return out
		case 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z':
			out[i] = 'A'
			return out
		}
	}
	return out
}
