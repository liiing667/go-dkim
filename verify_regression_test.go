package dkim

import (
	"bytes"
	"strings"
	"testing"
)

// Sign a message with two instances of a security-related header field, then
// inject a third instance at the bottom of the header block. The signature
// must not verify: a verifier cannot be tricked into accepting a replaced
// security header, even when verification is retried.
func TestVerify_rejectsInjectedDuplicateHeader(t *testing.T) {
	original := strings.NewReader(
		"From: Joe SixPack <joe@football.example.com>\r\n" +
			"To: Suzie Q <suzie@shopping.example.net>\r\n" +
			"X-Security: on\r\n" +
			"Subject: Is dinner ready?\r\n" +
			"X-Security: on\r\n" +
			"\r\n" +
			mailBodyString,
	)

	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
		HeaderKeys: []string{
			"From",
			"To",
			"X-Security",
			"X-Security",
			"Subject",
		},
	}

	var signed bytes.Buffer
	if err := Sign(&signed, original, options); err != nil {
		t.Fatalf("Expected no error while signing mail, got: %v", err)
	}

	// An attacker prepends (i.e. injects at the bottom of the header block,
	// right before the body) an additional X-Security field disabling the
	// protection.
	injected := strings.Replace(
		signed.String(),
		"Subject: Is dinner ready?\r\n",
		"Subject: Is dinner ready?\r\nX-Security: off\r\n",
		1,
	)

	for attempt := 0; attempt < 3; attempt++ {
		verifications, err := Verify(strings.NewReader(injected))
		if err != nil {
			t.Fatalf("Attempt %v: expected no error from Verify, got: %v", attempt, err)
		}
		if len(verifications) != 1 {
			t.Fatalf("Attempt %v: expected exactly one verification, got %v", attempt, len(verifications))
		}
		if verifications[0].Err == nil {
			t.Fatalf("Attempt %v: expected the signature to fail after header injection", attempt)
		}
	}
}

// Re-verifying the same untouched signed message multiple times must always
// succeed with the same result. The body is fully buffered before the
// signature checks, so re-running Verify (a retry or a restart) reproduces
// the exact same signed scope instead of consuming an empty body.
func TestVerify_retryProducesStableResult(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	}

	var signed bytes.Buffer
	if err := Sign(&signed, r, options); err != nil {
		t.Fatalf("Expected no error while signing mail, got: %v", err)
	}

	for attempt := 0; attempt < 3; attempt++ {
		verifications, err := Verify(strings.NewReader(signed.String()))
		if err != nil {
			t.Fatalf("Attempt %v: expected no error from Verify, got: %v", attempt, err)
		}
		if len(verifications) != 1 {
			t.Fatalf("Attempt %v: expected exactly one verification, got %v", attempt, len(verifications))
		}
		if verifications[0].Err != nil {
			t.Fatalf("Attempt %v: expected the signature to verify, got: %v", attempt, verifications[0].Err)
		}
	}
}

// A message carrying several signatures must keep verifying all of them
// deterministically: each signature gets its own independent body reader, so
// one signature's body consumption cannot affect the others.
func TestVerify_multipleSignaturesUseIndependentBodyReaders(t *testing.T) {
	for attempt := 0; attempt < 3; attempt++ {
		verifications, err := Verify(newMailStringReader(verifiedEd25519MailString))
		if err != nil {
			t.Fatalf("Attempt %v: expected no error from Verify, got: %v", attempt, err)
		}
		if len(verifications) != 2 {
			t.Fatalf("Attempt %v: expected exactly two verifications, got %v", attempt, len(verifications))
		}
		for i, v := range verifications {
			if v == nil {
				t.Fatalf("Attempt %v: verification %v is nil", attempt, i)
			}
			if v.Err != nil {
				t.Fatalf("Attempt %v: expected signature %v to verify, got: %v", attempt, i, v.Err)
			}
		}
	}
}
