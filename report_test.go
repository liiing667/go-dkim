package dkim

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func testRSAQueryResult() *queryResult {
	return &queryResult{
		Verifier:  rsaVerifier{&testPrivateKey.PublicKey},
		KeyAlgo:   "rsa",
		HashAlgos: []string{"sha256"},
		Services:  []string{"email"},
	}
}

func withTestQuery(fn func(domain, selector string) (*queryResult, error)) func() {
	original := queryMethods[QueryMethodDNSTXT]
	queryMethods[QueryMethodDNSTXT] = fn
	return func() {
		queryMethods[QueryMethodDNSTXT] = original
	}
}

func signTwice(t *testing.T, first, second *SignOptions, mail string) string {
	t.Helper()

	var firstSigned bytes.Buffer
	if err := Sign(&firstSigned, strings.NewReader(mail), first); err != nil {
		t.Fatalf("First signing failed: %v", err)
	}

	var secondSigned bytes.Buffer
	if err := Sign(&secondSigned, bytes.NewReader(firstSigned.Bytes()), second); err != nil {
		t.Fatalf("Second signing failed: %v", err)
	}
	return secondSigned.String()
}

func TestVerifyMessageMultipleSignaturesAllPass(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		return testRSAQueryResult(), nil
	})()

	// The second Sign call prepends the second signature, so the report must
	// preserve the physical header order: beta (top), then alpha (bottom).
	signed := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "one", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "two", Signer: testPrivateKey},
		mailString,
	)

	report, err := VerifyMessage(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if report.Conclusion != StatusPass {
		t.Fatalf("Expected message conclusion %q, got %q", StatusPass, report.Conclusion)
	}
	if !report.Trusted() {
		t.Error("Expected a message with only passing signatures to be trusted")
	}
	if len(report.Signatures) != 2 {
		t.Fatalf("Expected two signatures, got %d", len(report.Signatures))
	}

	wantDomains := []string{"beta.example", "alpha.example"}
	wantSelectors := []string{"two", "one"}
	for i, sig := range report.Signatures {
		if sig.Index != i {
			t.Errorf("Signature %d has index %d", i, sig.Index)
		}
		if sig.Domain != wantDomains[i] {
			t.Errorf("Signature %d domain = %q, want %q", i, sig.Domain, wantDomains[i])
		}
		if sig.Selector != wantSelectors[i] {
			t.Errorf("Signature %d selector = %q, want %q", i, sig.Selector, wantSelectors[i])
		}
		if sig.DNSStatus != DNSOK {
			t.Errorf("Signature %d DNS status = %q, want %q", i, sig.DNSStatus, DNSOK)
		}
		if sig.Result != StatusPass {
			t.Errorf("Signature %d result = %q, want %q", i, sig.Result, StatusPass)
		}
		if sig.Error != "" {
			t.Errorf("Signature %d unexpectedly has error %q", i, sig.Error)
		}
	}
}

func TestVerifyMessageRetryProducesSameOrderedReport(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		return testRSAQueryResult(), nil
	})()

	signed := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "one", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "two", Signer: testPrivateKey},
		mailString,
	)

	first, err := VerifyMessage(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("First VerifyMessage failed: %v", err)
	}
	second, err := VerifyMessage(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Second VerifyMessage failed: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("Re-verifying the same message changed the report:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

func TestVerifyMessageRetainsTemporaryFailureNextToPass(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		if selector == "temp" {
			return nil, tempFailError("key unavailable: test")
		}
		return testRSAQueryResult(), nil
	})()

	signed := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "temp", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "pass", Signer: testPrivateKey},
		mailString,
	)

	report, err := VerifyMessage(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if len(report.Signatures) != 2 {
		t.Fatalf("Expected two signatures, got %d", len(report.Signatures))
	}
	if report.Signatures[0].Result != StatusPass || report.Signatures[0].DNSStatus != DNSOK {
		t.Errorf("Expected the first signature to pass, got %+v", report.Signatures[0])
	}
	if report.Signatures[1].Result != StatusTempError || report.Signatures[1].DNSStatus != DNSTempError {
		t.Errorf("Expected the second signature to keep its temporary failure, got %+v", report.Signatures[1])
	}
	if report.Conclusion != StatusTempError {
		t.Errorf("Expected message conclusion %q, got %q", StatusTempError, report.Conclusion)
	}
	if report.Trusted() {
		t.Error("A message with a temporary signature failure must not be trusted")
	}
}

func TestVerifyMessageRetainsRevokedKeyNextToPass(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		if selector == "revoked" {
			return nil, ErrKeyRevoked
		}
		return testRSAQueryResult(), nil
	})()

	signed := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "revoked", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "pass", Signer: testPrivateKey},
		mailString,
	)

	report, err := VerifyMessage(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if len(report.Signatures) != 2 {
		t.Fatalf("Expected two signatures, got %d", len(report.Signatures))
	}
	if report.Signatures[0].Result != StatusPass {
		t.Errorf("Expected the first signature to pass, got %+v", report.Signatures[0])
	}
	if report.Signatures[1].Result != StatusPermError {
		t.Errorf("Expected the revoked signature to be a permanent failure, got %+v", report.Signatures[1])
	}
	if report.Signatures[1].DNSStatus != DNSRevoked {
		t.Errorf("Expected revoked DNS status, got %q", report.Signatures[1].DNSStatus)
	}
	if !IsKeyRevoked(ErrKeyRevoked) {
		t.Error("Expected ErrKeyRevoked to be recognized")
	}
	if report.Conclusion != StatusPermError {
		t.Errorf("Expected message conclusion %q, got %q", StatusPermError, report.Conclusion)
	}
}

func TestVerifyMessageMalformedSignatureDoesNotHideLaterPass(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		return testRSAQueryResult(), nil
	})()

	valid := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "one", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "two", Signer: testPrivateKey},
		mailString,
	)
	malformed := "DKIM-Signature: v=2; d=bad.example; s=bad; h=from; bh=AAAA; b=AAAA\r\n"
	message := malformed + valid

	report, err := VerifyMessage(strings.NewReader(message))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if len(report.Signatures) != 3 {
		t.Fatalf("Expected three signatures, got %d", len(report.Signatures))
	}
	if report.Signatures[0].Result != StatusPermError {
		t.Errorf("Expected malformed signature to be a permanent failure, got %+v", report.Signatures[0])
	}
	if report.Signatures[0].Domain != "bad.example" {
		t.Errorf("Expected frozen malformed-signature domain, got %q", report.Signatures[0].Domain)
	}
	if report.Signatures[1].Result != StatusPass || report.Signatures[2].Result != StatusPass {
		t.Errorf("Expected later signatures to keep passing, got %+v and %+v", report.Signatures[1], report.Signatures[2])
	}
	if report.Conclusion != StatusPermError {
		t.Errorf("Expected message conclusion %q, got %q", StatusPermError, report.Conclusion)
	}

	// The historical API must still return the same per-signature results.
	verifications, err := Verify(strings.NewReader(message))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if len(verifications) != 3 {
		t.Fatalf("Expected three legacy verifications, got %d", len(verifications))
	}
	if !IsPermFail(verifications[0].Err) || verifications[1].Err != nil || verifications[2].Err != nil {
		t.Errorf("Legacy per-signature results changed: %+v", verifications)
	}
	if got := OverallStatus(verifications); got != StatusPermError {
		t.Errorf("OverallStatus of legacy results = %q, want %q", got, StatusPermError)
	}
}

func TestVerifyMessageTamperedBodyIsAFailForEverySignature(t *testing.T) {
	defer withTestQuery(func(domain, selector string) (*queryResult, error) {
		return testRSAQueryResult(), nil
	})()

	signed := signTwice(t,
		&SignOptions{Domain: "alpha.example", Selector: "one", Signer: testPrivateKey},
		&SignOptions{Domain: "beta.example", Selector: "two", Signer: testPrivateKey},
		mailString,
	)
	tampered := strings.Replace(signed, "We lost the game.", "We won the game.", 1)

	report, err := VerifyMessage(strings.NewReader(tampered))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if len(report.Signatures) != 2 {
		t.Fatalf("Expected two signatures, got %d", len(report.Signatures))
	}
	for i, sig := range report.Signatures {
		if sig.Result != StatusFail {
			t.Errorf("Signature %d result = %q, want %q", i, sig.Result, StatusFail)
		}
		if sig.DNSStatus != DNSOK {
			t.Errorf("Signature %d should still record its successful DNS lookup, got %q", i, sig.DNSStatus)
		}
	}
	if report.Conclusion != StatusFail {
		t.Errorf("Expected message conclusion %q, got %q", StatusFail, report.Conclusion)
	}
}

func TestVerifyMessageNoSignatures(t *testing.T) {
	report, err := VerifyMessage(strings.NewReader(mailString))
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if len(report.Signatures) != 0 {
		t.Fatalf("Expected no signatures, got %d", len(report.Signatures))
	}
	if report.Conclusion != StatusNone {
		t.Errorf("Expected conclusion %q, got %q", StatusNone, report.Conclusion)
	}
	if report.Trusted() {
		t.Error("An unsigned message must not be reported as trusted")
	}
	if len(report.ID) != 64 {
		t.Errorf("Expected a stable SHA-256 message ID, got %q", report.ID)
	}

	verifications, err := Verify(strings.NewReader(mailString))
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if len(verifications) != 0 {
		t.Errorf("Expected no legacy verifications, got %d", len(verifications))
	}
	if got := OverallStatus(verifications); got != StatusNone {
		t.Errorf("OverallStatus of an unsigned message = %q, want %q", got, StatusNone)
	}
}

func TestConclusionKeepsEveryNonPassingSignature(t *testing.T) {
	tests := []struct {
		name    string
		results []Status
		want    Status
	}{
		{name: "none", results: nil, want: StatusNone},
		{name: "all pass", results: []Status{StatusPass, StatusPass}, want: StatusPass},
		{name: "one fail", results: []Status{StatusPass, StatusFail}, want: StatusFail},
		{name: "one temporary error", results: []Status{StatusPass, StatusTempError}, want: StatusTempError},
		{name: "one permanent error", results: []Status{StatusPass, StatusPermError}, want: StatusPermError},
		{name: "fail is worse than temporary error", results: []Status{StatusTempError, StatusFail}, want: StatusFail},
		{name: "permanent error is worst", results: []Status{StatusFail, StatusPermError}, want: StatusPermError},
	}
	for _, test := range tests {
		signatures := make([]*SignatureReport, len(test.results))
		for i, result := range test.results {
			signatures[i] = &SignatureReport{Index: i, Result: result}
		}
		if got := conclusionFor(signatures); got != test.want {
			t.Errorf("%s: conclusion = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestStatusForError(t *testing.T) {
	tests := []struct {
		err  error
		want Status
	}{
		{nil, StatusPass},
		{tempFailError("temporary"), StatusTempError},
		{permFailError("permanent"), StatusPermError},
		{ErrKeyRevoked, StatusPermError},
		{failError("bad signature"), StatusFail},
		{errTestUnclassified, StatusError},
	}
	for _, test := range tests {
		if got := StatusForError(test.err); got != test.want {
			t.Errorf("StatusForError(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

var errTestUnclassified = &testUnclassifiedError{}

type testUnclassifiedError struct{}

func (*testUnclassifiedError) Error() string { return "unclassified" }
