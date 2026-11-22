package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func gsb32029PublicKeyTXT(t *testing.T, pub interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; p=" + base64.StdEncoding.EncodeToString(der)
}

func gsb32029InstallKeyQuery(t *testing.T, result **queryResult, queryErr *error) func() {
	t.Helper()
	orig := queryMethods[QueryMethodDNSTXT]
	queryMethods[QueryMethodDNSTXT] = func(domain, selector string) (*queryResult, error) {
		if domain == "example.com" {
			return *result, *queryErr
		}
		return orig(domain, selector)
	}
	return func() { queryMethods[QueryMethodDNSTXT] = orig }
}

func TestGSB32029KeyCacheFreezesGenerationAndSelector(t *testing.T) {
	oldResult, err := parsePublicKey(dnsPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	newResult, err := parsePublicKey(gsb32029PublicKeyTXT(t, &newKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	var result = oldResult
	var queryErr error
	defer gsb32029InstallKeyQuery(t, &result, &queryErr)()

	cache := NewKeyCache()
	first, err := cache.Resolve("example.com", "brisbane")
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation == 0 {
		t.Fatal("expected a non-zero key generation")
	}
	if first.Selector != "brisbane" || first.Domain != "example.com" {
		t.Fatalf("unexpected identity: %+v", first)
	}

	result = newResult
	second, err := cache.Resolve("example.com", "brisbane")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("rotation did not advance generation: %v then %v",
			first.Generation, second.Generation)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("rotation reused the old key fingerprint")
	}
	if first.Generation != 1 {
		t.Fatalf("frozen key generation drifted to %v", first.Generation)
	}

	// A different selector must never reuse the same cache entry, even when
	// the DNS name shares the domain.
	result = oldResult
	other, err := cache.Resolve("example.com", "other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Generation <= second.Generation {
		t.Fatalf("new selector reused a generation: %v", other.Generation)
	}
	if other.Fingerprint != first.Fingerprint {
		t.Fatal("unexpected key for the other selector")
	}
}

func TestGSB32029VerifyReportFreezesKeyIdentity(t *testing.T) {
	oldResult, err := parsePublicKey(dnsPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	newResult, err := parsePublicKey(gsb32029PublicKeyTXT(t, &newKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	var result = oldResult
	var queryErr error
	defer gsb32029InstallKeyQuery(t, &result, &queryErr)()

	cache := NewKeyCache()
	verifs, err := VerifyWithOptions(newMailStringReader(verifiedMailString), &VerifyOptions{
		Reports:  true,
		KeyCache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifs) != 1 {
		t.Fatalf("expected one verification, got %v", len(verifs))
	}
	v := verifs[0]
	if v.Err != nil {
		t.Fatalf("expected a valid signature, got: %v", v.Err)
	}
	if v.Report == nil {
		t.Fatal("expected a verification report")
	}
	if v.Report.Selector != "brisbane" || v.Report.Domain != "example.com" {
		t.Fatalf("report lost signature identity: %+v", v.Report)
	}
	if v.Report.KeyGeneration != 1 {
		t.Fatalf("expected generation 1, got %v", v.Report.KeyGeneration)
	}
	if v.Report.KeyFingerprint == "" || v.Report.KeyDigest != v.Report.KeyFingerprint {
		t.Fatalf("report lost key fingerprint: %+v", v.Report)
	}
	if v.Report.CacheSource != CacheSourceDNS {
		t.Fatalf("expected DNS source, got %q", v.Report.CacheSource)
	}
	if v.Report.BodyDigest == "" || v.Report.HeaderDigest == "" {
		t.Fatalf("report lost message digests: %+v", v.Report)
	}
	if v.Report.Stage != VerificationStageCryptoVerify {
		t.Fatalf("expected crypto-verify stage, got %q", v.Report.Stage)
	}
	if v.Report.Key == nil || v.Report.Key.Generation != v.Report.KeyGeneration {
		t.Fatal("report does not expose the frozen key snapshot")
	}

	// Rotate the same selector to a new key. The new message must use the new
	// generation and must not be endorsed by the cached old key.
	result = newResult
	verifs, err = VerifyWithOptions(newMailStringReader(verifiedMailString), &VerifyOptions{
		Reports:  true,
		KeyCache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	v = verifs[0]
	if v.Err == nil || !isFail(v.Err) {
		t.Fatalf("expected the rotated key to reject the old signature, got: %v", v.Err)
	}
	if v.Report == nil || v.Report.KeyGeneration != 2 {
		t.Fatalf("expected generation 2 after rotation, got %+v", v.Report)
	}
	if v.Report.Stage != VerificationStageCryptoVerify {
		t.Fatalf("expected crypto-verify failure stage, got %q", v.Report.Stage)
	}

	// The first verification's frozen snapshot must not have moved.
	if first, ok := cache.Peek("example.com", "brisbane"); !ok || first.Generation != 2 {
		t.Fatalf("cache did not commit the complete new generation: %+v", first)
	}
}

func TestGSB32029KeyQueryFailureLeavesOldGenerationIntact(t *testing.T) {
	oldResult, err := parsePublicKey(dnsPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	newResult, err := parsePublicKey(gsb32029PublicKeyTXT(t, &newKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	var result = oldResult
	var queryErr error
	defer gsb32029InstallKeyQuery(t, &result, &queryErr)()

	cache := NewKeyCache()
	if _, err := cache.Resolve("example.com", "brisbane"); err != nil {
		t.Fatal(err)
	}

	queryErr = tempFailError("key unavailable")
	result = nil
	verifs, err := VerifyWithOptions(newMailStringReader(verifiedMailString), &VerifyOptions{
		Reports:  true,
		KeyCache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifs) != 1 || !IsTempFail(verifs[0].Err) {
		t.Fatalf("expected a temporary key query failure, got %+v", verifs)
	}
	if verifs[0].Report.Stage != VerificationStageKeyQuery {
		t.Fatalf("expected key-query stage, got %q", verifs[0].Report.Stage)
	}

	old, ok := cache.Peek("example.com", "brisbane")
	if !ok || old.Generation != 1 {
		t.Fatalf("failed query damaged the committed generation: %+v", old)
	}

	queryErr = nil
	result = newResult
	verifs, err = VerifyWithOptions(newMailStringReader(verifiedMailString), &VerifyOptions{
		Reports:  true,
		KeyCache: cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifs[0].Err == nil {
		t.Fatal("expected the old signature to fail after the key rotation")
	}
	if verifs[0].Report.KeyGeneration != 2 {
		t.Fatalf("expected a new complete generation, got %+v", verifs[0].Report)
	}
}

func TestGSB32029KeyCacheSnapshotRoundTrip(t *testing.T) {
	result, err := parsePublicKey(dnsPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var queryResultPtr = result
	var queryErr error
	defer gsb32029InstallKeyQuery(t, &queryResultPtr, &queryErr)()

	cache := NewKeyCache()
	key, err := cache.Resolve("example.com", "brisbane")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cache.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewKeyCacheFromSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := restored.Get("example.com", "brisbane")
	if !ok {
		t.Fatal("restored cache lost the selector")
	}
	if got.Generation != key.Generation || got.Fingerprint != key.Fingerprint {
		t.Fatalf("restored identity mismatch: %+v vs %+v", got, key)
	}
	if got.Selector != "brisbane" {
		t.Fatalf("restored selector mismatch: %q", got.Selector)
	}
}

func TestGSB32029PublicKeyTXTShapes(t *testing.T) {
	// A single key is still accepted.
	single, err := parsePublicKey(dnsPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if single.Verifier == nil {
		t.Fatal("single key did not parse")
	}

	// Long keys are split into multiple TXT strings by DNS; queryDNSTXT
	// concatenates them before parsing.
	mid := len(dnsPublicKey) / 2
	joined, err := parsePublicKey(dnsPublicKey[:mid] + dnsPublicKey[mid:])
	if err != nil {
		t.Fatal(err)
	}
	if joined.Verifier == nil {
		t.Fatal("multiple TXT parts did not parse")
	}

	// An empty TXT answer remains a permanent key syntax error.
	if _, err := parsePublicKey(""); err == nil || !IsPermFail(err) {
		t.Fatalf("expected a permanent failure for an empty TXT answer, got: %v", err)
	}
	if _, err := parsePublicKey("v=DKIM1; p="); err == nil || !IsPermFail(err) {
		t.Fatalf("expected a permanent failure for a revoked key, got: %v", err)
	}
}
