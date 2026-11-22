package dkim

import (
	"bytes"
	"io"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func isolateDuplicateHeaderRand() func() {
	old := randReader
	randReader = rand.New(rand.NewSource(1))
	return func() {
		randReader = old
	}
}

func signDuplicateHeaderMessage(t *testing.T, message string, options *SignOptions) string {
	t.Helper()

	var signed bytes.Buffer
	if err := Sign(&signed, strings.NewReader(message), options); err != nil {
		t.Fatalf("Expected no error while signing mail, got: %v", err)
	}
	return signed.String()
}

func signDuplicateHeaderSignature(t *testing.T, message string, options *SignOptions) (string, []HeaderInstance) {
	t.Helper()

	signer, err := NewSigner(options)
	if err != nil {
		t.Fatalf("Expected no error while creating signer, got: %v", err)
	}
	if _, err := io.WriteString(signer, message); err != nil {
		t.Fatalf("Expected no error while writing message, got: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Fatalf("Expected no error while closing signer, got: %v", err)
	}
	return signer.Signature(), signer.HeaderInstances()
}

func duplicateHeaderRaw(instances []HeaderInstance) []string {
	raw := make([]string, len(instances))
	for i, instance := range instances {
		raw[i] = instance.Raw
	}
	return raw
}

func TestSignVerify_DuplicateHeaderDeclarationOrder(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"Received: first\r\n" +
		"To: Suzie Q <suzie@shopping.example.net>\r\n" +
		"Subject: folded\r\n\t value\r\n" +
		"Received: second\r\n" +
		"\r\n" +
		"body\r\n"

	headerKeys := []string{"Received", "From", "To", "Subject", "Received"}
	signed := signDuplicateHeaderMessage(t, message, &SignOptions{
		Domain:     "example.org",
		Selector:   "brisbane",
		Signer:     testPrivateKey,
		HeaderKeys: headerKeys,
	})

	verifications, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected no error while verifying mail, got: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("Expected one verification, got %v", len(verifications))
	}
	v := verifications[0]
	if v.Err != nil {
		t.Fatalf("Expected the signature to verify, got: %v", v.Err)
	}
	if !reflect.DeepEqual(v.HeaderKeys, headerKeys) {
		t.Errorf("Expected declaration order %v, got %v", headerKeys, v.HeaderKeys)
	}

	// The signature field is prepended to the original message, so every
	// original header index moves by one.
	wantIndexes := []int{5, 1, 3, 4, 2}
	wantNames := []string{"Received", "From", "To", "Subject", "Received"}
	wantRaw := []string{
		"Received: second\r\n",
		"From: Joe SixPack <joe@football.example.com>\r\n",
		"To: Suzie Q <suzie@shopping.example.net>\r\n",
		"Subject: folded\r\n\t value\r\n",
		"Received: first\r\n",
	}
	if len(v.HeaderInstances) != len(wantIndexes) {
		t.Fatalf("Expected %v consumed header instances, got %v", len(wantIndexes), v.HeaderInstances)
	}
	for i, instance := range v.HeaderInstances {
		if instance.Index != wantIndexes[i] || instance.Name != wantNames[i] || instance.Raw != wantRaw[i] {
			t.Errorf("Instance %v = %+v, want index=%v name=%q raw=%q",
				i, instance, wantIndexes[i], wantNames[i], wantRaw[i])
		}
	}
}

func TestSignVerify_CommonDuplicateReceived(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "Received: top\r\n" +
		"From: Joe SixPack <joe@football.example.com>\r\n" +
		"Received: middle\r\n" +
		"To: Suzie Q <suzie@shopping.example.net>\r\n" +
		"Received: bottom\r\n" +
		"Subject: duplicate received\r\n" +
		"\r\n" +
		"body\r\n"

	signed := signDuplicateHeaderMessage(t, message, &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	})

	verifications, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected no error while verifying mail, got: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("Expected one verification, got %v", len(verifications))
	}
	v := verifications[0]
	if v.Err != nil {
		t.Fatalf("Expected the signature to verify, got: %v", v.Err)
	}

	var received int
	for _, key := range v.HeaderKeys {
		if strings.EqualFold(key, "Received") {
			received++
		}
	}
	if received != 3 {
		t.Fatalf("Expected all three Received instances in h=, got %v in %v", received, v.HeaderKeys)
	}

	want := []string{
		"Received: bottom\r\n",
		"From: Joe SixPack <joe@football.example.com>\r\n",
		"Received: middle\r\n",
		"To: Suzie Q <suzie@shopping.example.net>\r\n",
		"Received: top\r\n",
		"Subject: duplicate received\r\n",
	}
	if got := duplicateHeaderRaw(v.HeaderInstances); !reflect.DeepEqual(got, want) {
		t.Errorf("Expected consumed headers\n%q\nbut got\n%q", want, got)
	}
}

func TestVerify_RetryAfterTemporaryKeyFailureKeepsHeaderBinding(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"Received: first\r\n" +
		"Subject: retry\r\n" +
		"Received: second\r\n" +
		"\r\n" +
		"body\r\n"

	signed := signDuplicateHeaderMessage(t, message, &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	})

	oldQuery := queryMethods[QueryMethodDNSTXT]
	calls := 0
	queryMethods[QueryMethodDNSTXT] = func(domain, selector string) (*queryResult, error) {
		calls++
		if calls == 1 {
			return nil, tempFailError("synthetic temporary failure")
		}
		return oldQuery(domain, selector)
	}
	defer func() {
		queryMethods[QueryMethodDNSTXT] = oldQuery
	}()

	first, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected temp failure to be reported per signature, got: %v", err)
	}
	if len(first) != 1 || first[0] == nil || !IsTempFail(first[0].Err) {
		t.Fatalf("Expected one temporary verification failure, got %+v", first)
	}

	second, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected retry to return a verification, got: %v", err)
	}
	if len(second) != 1 || second[0] == nil || second[0].Err != nil {
		t.Fatalf("Expected retry to verify, got %+v", second)
	}

	if !reflect.DeepEqual(first[0].HeaderInstances, second[0].HeaderInstances) {
		t.Errorf("Expected retry to keep the same header binding, got\n%+v\nand\n%+v",
			first[0].HeaderInstances, second[0].HeaderInstances)
	}
	if len(second[0].HeaderInstances) != 4 {
		t.Errorf("Expected four consumed header instances, got %+v", second[0].HeaderInstances)
	}
}

func TestVerify_FailedRetryKeepsHeaderBinding(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const original = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"Received: first\r\n" +
		"Subject: retry\r\n" +
		"Received: second\r\n" +
		"\r\n" +
		"original body\r\n"
	signed := signDuplicateHeaderMessage(t, original, &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	})
	tampered := strings.Replace(signed, "original body\r\n", "tampered body\r\n", 1)

	var want []HeaderInstance
	for attempt := 0; attempt < 3; attempt++ {
		verifications, err := Verify(strings.NewReader(tampered))
		if err != nil {
			t.Fatalf("Attempt %v: expected per-signature failure, got: %v", attempt, err)
		}
		if len(verifications) != 1 || verifications[0] == nil {
			t.Fatalf("Attempt %v: expected one verification, got %+v", attempt, verifications)
		}
		v := verifications[0]
		if v.Err == nil {
			t.Fatalf("Attempt %v: expected the tampered body to fail", attempt)
		}
		if attempt == 0 {
			want = v.HeaderInstances
			if len(want) == 0 {
				t.Fatal("Expected failed verification to report consumed header instances")
			}
			continue
		}
		if !reflect.DeepEqual(v.HeaderInstances, want) {
			t.Errorf("Attempt %v: header binding changed from\n%+v\nto\n%+v",
				attempt, want, v.HeaderInstances)
		}
	}
}

func TestSignVerify_RelaxedFoldedWhitespace(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"Subject:   folded\r\n\t whitespace  here\r\n" +
		"To: Suzie Q <suzie@shopping.example.net>\r\n" +
		"\r\n" +
		"body\r\n"

	signed := signDuplicateHeaderMessage(t, message, &SignOptions{
		Domain:                 "example.org",
		Selector:               "brisbane",
		Signer:                 testPrivateKey,
		HeaderCanonicalization: CanonicalizationRelaxed,
		BodyCanonicalization:   CanonicalizationRelaxed,
	})

	verifications, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected no error while verifying mail, got: %v", err)
	}
	if len(verifications) != 1 || verifications[0] == nil || verifications[0].Err != nil {
		t.Fatalf("Expected the relaxed signature to verify, got %+v", verifications)
	}

	var subject *HeaderInstance
	for i := range verifications[0].HeaderInstances {
		instance := &verifications[0].HeaderInstances[i]
		if instance.Name == "Subject" {
			subject = instance
			break
		}
	}
	if subject == nil {
		t.Fatal("Expected the Subject header instance in the report")
	}
	if subject.Raw != "Subject:   folded\r\n\t whitespace  here\r\n" {
		t.Errorf("Expected folded Subject bytes to be preserved, got %q", subject.Raw)
	}
}

func TestSignVerify_Ed25519SignatureField(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"To: Suzie Q <suzie@shopping.example.net>\r\n" +
		"Subject: ed25519\r\n" +
		"\r\n" +
		"body\r\n"

	signed := signDuplicateHeaderMessage(t, message, &SignOptions{
		Domain:   "football.example.com",
		Selector: "brisbane",
		Signer:   testEd25519PrivateKey,
	})

	verifications, err := Verify(strings.NewReader(signed))
	if err != nil {
		t.Fatalf("Expected no error while verifying Ed25519 mail, got: %v", err)
	}
	if len(verifications) != 1 || verifications[0] == nil || verifications[0].Err != nil {
		t.Fatalf("Expected the Ed25519 signature to verify, got %+v", verifications)
	}
}

func TestSignVerify_MultipleSignaturesBindIndependently(t *testing.T) {
	restoreRand := isolateDuplicateHeaderRand()
	defer restoreRand()

	const message = "From: Joe SixPack <joe@football.example.com>\r\n" +
		"Received: first\r\n" +
		"To: Suzie Q <suzie@shopping.example.net>\r\n" +
		"Subject: multiple signatures\r\n" +
		"Received: second\r\n" +
		"\r\n" +
		"body\r\n"
	options := &SignOptions{
		Domain:     "example.org",
		Selector:   "brisbane",
		Signer:     testPrivateKey,
		HeaderKeys: []string{"Received", "From", "To", "Subject", "Received"},
	}

	firstField, firstInstances := signDuplicateHeaderSignature(t, message, options)
	secondField, secondInstances := signDuplicateHeaderSignature(t, message, options)
	if !reflect.DeepEqual(firstInstances, secondInstances) {
		t.Fatalf("Expected identical signing bindings, got\n%+v\nand\n%+v",
			firstInstances, secondInstances)
	}

	verifications, err := Verify(strings.NewReader(firstField + secondField + message))
	if err != nil {
		t.Fatalf("Expected no error while verifying mail, got: %v", err)
	}
	if len(verifications) != 2 {
		t.Fatalf("Expected two verifications, got %v", len(verifications))
	}
	for i, v := range verifications {
		if v == nil || v.Err != nil {
			t.Fatalf("Expected signature %v to verify, got %+v", i, v)
		}
		if len(v.HeaderInstances) != len(firstInstances) {
			t.Fatalf("Expected signature %v to consume %v headers, got %+v",
				i, len(firstInstances), v.HeaderInstances)
		}
		for j, instance := range v.HeaderInstances {
			if instance.Raw != firstInstances[j].Raw {
				t.Errorf("Signature %v instance %v = %q, want %q",
					i, j, instance.Raw, firstInstances[j].Raw)
			}
			if instance.Index != firstInstances[j].Index+2 {
				t.Errorf("Signature %v instance %v index = %v, want %v",
					i, j, instance.Index, firstInstances[j].Index+2)
			}
		}
	}
}
