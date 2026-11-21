package dkim

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

var errTestKeyQuery = errors.New("dkim: test key query failure")

// A key query failure for one signature must not prevent the other
// signatures from being verified, and retrying the verification must
// produce the same result.
func TestVerify_multipleSignaturesKeyQueryError(t *testing.T) {
	origQuery := queryMethods[QueryMethodDNSTXT]
	defer func() { queryMethods[QueryMethodDNSTXT] = origQuery }()
	queryMethods[QueryMethodDNSTXT] = func(domain, selector string) (*queryResult, error) {
		if domain == "football.example.com" && selector == "brisbane" {
			return nil, errTestKeyQuery
		}
		return origQuery(domain, selector)
	}

	for attempt := 0; attempt < 3; attempt++ {
		r := newMailStringReader(verifiedEd25519MailString)
		verifications, err := Verify(r)
		if err != nil {
			t.Fatalf("Attempt %v: expected no error while verifying signatures, got: %v", attempt, err)
		}
		if len(verifications) != 2 {
			t.Fatalf("Attempt %v: expected exactly two verifications, got %v", attempt, len(verifications))
		}

		v := verifications[0]
		if v == nil {
			t.Fatalf("Attempt %v: expected a verification for the first signature, got nil", attempt)
		}
		if v.Domain != "football.example.com" {
			t.Errorf("Attempt %v: expected first verification domain to be %q, got %q", attempt, "football.example.com", v.Domain)
		}
		if v.Err != errTestKeyQuery {
			t.Errorf("Attempt %v: expected first verification error to be %v, got %v", attempt, errTestKeyQuery, v.Err)
		}

		v = verifications[1]
		if v == nil {
			t.Fatalf("Attempt %v: expected a verification for the second signature, got nil", attempt)
		}
		if v.Domain != "football.example.com" {
			t.Errorf("Attempt %v: expected second verification domain to be %q, got %q", attempt, "football.example.com", v.Domain)
		}
		if v.Err != nil {
			t.Errorf("Attempt %v: expected second signature to verify, got: %v", attempt, v.Err)
		}
	}
}

// A temporary key query failure for one signature must not change the
// outcome of the other signatures.
func TestVerify_multipleSignaturesKeyQueryTempFail(t *testing.T) {
	origQuery := queryMethods[QueryMethodDNSTXT]
	defer func() { queryMethods[QueryMethodDNSTXT] = origQuery }()
	queryMethods[QueryMethodDNSTXT] = func(domain, selector string) (*queryResult, error) {
		if domain == "football.example.com" && selector == "brisbane" {
			return nil, tempFailError("key unavailable")
		}
		return origQuery(domain, selector)
	}

	r := newMailStringReader(verifiedEd25519MailString)
	verifications, err := Verify(r)
	if err != nil {
		t.Fatalf("Expected no error while verifying signatures, got: %v", err)
	}
	if len(verifications) != 2 {
		t.Fatalf("Expected exactly two verifications, got %v", len(verifications))
	}
	if v := verifications[0]; v == nil || !IsTempFail(v.Err) {
		t.Errorf("Expected first verification to be a temporary failure, got %+v", v)
	}
	if v := verifications[1]; v == nil || v.Err != nil {
		t.Errorf("Expected second verification to succeed, got %+v", v)
	}
}

// Verifying the same message multiple times must always produce the same
// result, even though the body is consumed on each attempt.
func TestVerify_retry(t *testing.T) {
	for attempt := 0; attempt < 3; attempt++ {
		r := newMailStringReader(verifiedMailString)
		verifications, err := Verify(r)
		if err != nil {
			t.Fatalf("Attempt %v: expected no error while verifying signature, got: %v", attempt, err)
		}
		if len(verifications) != 1 {
			t.Fatalf("Attempt %v: expected exactly one verification, got %v", attempt, len(verifications))
		}
		if v := verifications[0]; !reflect.DeepEqual(testVerification, v) {
			t.Errorf("Attempt %v: expected verification to be \n%+v\n but got \n%+v", attempt, testVerification, v)
		}
	}
}

// Multiple messages can be verified concurrently, each body being consumed
// independently.
func TestVerify_concurrent(t *testing.T) {
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			r := newMailStringReader(verifiedEd25519MailString)
			verifications, err := Verify(r)
			if err != nil {
				errs <- fmt.Errorf("expected no error while verifying signatures, got: %v", err)
				return
			}
			if len(verifications) != 2 {
				errs <- fmt.Errorf("expected exactly two verifications, got %v", len(verifications))
				return
			}
			for _, v := range verifications {
				if v == nil {
					errs <- errors.New("expected a verification, got nil")
					return
				}
				if v.Err != nil {
					errs <- fmt.Errorf("expected no verification error, got: %v", v.Err)
					return
				}
			}
			errs <- nil
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
