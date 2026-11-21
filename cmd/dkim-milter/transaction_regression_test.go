package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/textproto"
	"strings"
	"testing"
)

func newDKIMTransactionTestSession(t *testing.T) (*session, func()) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Failed to generate test key:", err)
	}

	oldSignDomains := signDomains
	oldSelector := selector
	oldPrivateKey := privateKey
	oldIdentity := identity

	signDomains = stringSliceFlag{"example.org"}
	selector = "brisbane"
	privateKey = key
	identity = "mx.example.org"

	cleanup := func() {
		signDomains = oldSignDomains
		selector = oldSelector
		privateKey = oldPrivateKey
		identity = oldIdentity
	}

	return &session{}, cleanup
}

func writeDKIMTransactionTestMessage(t *testing.T, s *session, messageID, subject, body string, headers textproto.MIMEHeader) {
	t.Helper()

	fields := []struct {
		name  string
		value string
	}{
		{"From", "Joe SixPack <joe@example.org>"},
		{"To", "Suzie Q <suzie@example.net>"},
		{"Subject", subject},
		{"Date", "Fri, 11 Jul 2003 21:00:37 -0700 (PDT)"},
		{"Message-ID", messageID},
	}
	for _, field := range fields {
		if _, err := s.Header(field.name, field.value, nil); err != nil {
			t.Fatalf("Failed to write %v header: %v", field.name, err)
		}
	}
	if _, err := s.Headers(headers, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte(body), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
}

func dkimTransactionSignatureTag(t *testing.T, sig, tag string) string {
	t.Helper()

	prefix := tag + "="
	for _, part := range strings.Split(sig, ";") {
		part = strings.Join(strings.Fields(part), "")
		if strings.HasPrefix(part, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(part, prefix))
		}
	}
	t.Fatalf("Signature tag %q not found in %q", tag, sig)
	return ""
}

func TestTransactionRegressionSingleMessage(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	body := "Hello, world!\r\n"
	writeDKIMTransactionTestMessage(t, s, "<single@example.org>", "Single message", body, textproto.MIMEHeader{})

	resp, err := s.Body(nil)
	if err != nil {
		t.Fatal("Expected no error while finishing message, got:", err)
	}
	if resp == nil {
		t.Error("Expected an accept response")
	}
	if !s.committed {
		t.Error("Expected message to be committed")
	}
	if s.signer == nil {
		t.Fatal("Expected a signer")
	}
	if got := dkimTransactionSignatureTag(t, s.signer.Signature(), "d"); got != "example.org" {
		t.Errorf("Expected domain %q, got %q", "example.org", got)
	}
}

func TestTransactionRegressionRetryDoesNotMixSnapshots(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	// First message is abandoned after its headers and a partial body have
	// been accepted. A retry with the same SMTP message ID must not reuse any
	// of this data.
	writeDKIMTransactionTestMessage(t, s, "<retry@example.org>", "Old subject", "old body\r\n", textproto.MIMEHeader{})
	firstGeneration := s.generation

	body := "new body\r\n"
	writeDKIMTransactionTestMessage(t, s, "<retry@example.org>", "New subject", body, textproto.MIMEHeader{})

	if s.generation == firstGeneration {
		t.Fatal("Expected the retry to start a new message transaction")
	}
	if s.messageID != "<retry@example.org>" {
		t.Errorf("Expected message ID to be frozen for the retry, got %q", s.messageID)
	}
	if s.bodyLen != int64(len(body)) {
		t.Errorf("Expected body length %v, got %v", len(body), s.bodyLen)
	}

	resp, err := s.Body(nil)
	if err != nil {
		t.Fatal("Expected no error while finishing retried message, got:", err)
	}
	if resp == nil {
		t.Error("Expected an accept response")
	}

	sum := sha256.Sum256([]byte(body))
	wantBodyHash := base64.StdEncoding.EncodeToString(sum[:])
	gotBodyHash := dkimTransactionSignatureTag(t, s.signer.Signature(), "bh")
	if gotBodyHash != wantBodyHash {
		t.Errorf("Expected body hash %q, got %q", wantBodyHash, gotBodyHash)
	}

	sum = sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); !strings.Contains(s.transactionEvidenceLocked(), got) {
		t.Errorf("Expected report evidence to contain body digest %q, got %q", got, s.transactionEvidenceLocked())
	}
}

func TestTransactionRegressionEmptySignatureHeader(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	// An empty DKIM-Signature header is a permanent verification failure, but
	// it must not prevent the milter from accepting and signing the message.
	fields := []struct {
		name  string
		value string
	}{
		{"From", "Joe SixPack <joe@example.org>"},
		{"Message-ID", "<empty-signature@example.org>"},
		{"DKIM-Signature", ""},
		{"Subject", "Empty signature"},
	}
	for _, field := range fields {
		if _, err := s.Header(field.name, field.value, nil); err != nil {
			t.Fatalf("Failed to write %v header: %v", field.name, err)
		}
	}
	if _, err := s.Headers(textproto.MIMEHeader{}, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte("body\r\n"), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}

	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected no error while finishing message, got:", err)
	}
	if len(s.verifs) != 1 {
		t.Fatalf("Expected one verification, got %v", len(s.verifs))
	}
	if s.verifs[0].Err == nil {
		t.Error("Expected the empty signature to fail verification")
	}
	if s.signer == nil {
		t.Error("Expected the message to be signed")
	}
}

func TestTransactionRegressionAbortCancelsBackgroundWork(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	writeDKIMTransactionTestMessage(t, s, "<abort@example.org>", "Abort", "partial body\r\n", textproto.MIMEHeader{})

	s.Abort()
	if s.active {
		t.Error("Expected aborted session to be inactive")
	}
	if s.signer != nil || s.pw != nil {
		t.Error("Expected abort to cancel signer and verification streams")
	}

	// A new message on the same session must still be accepted cleanly.
	writeDKIMTransactionTestMessage(t, s, "<after-abort@example.org>", "After abort", "complete body\r\n", textproto.MIMEHeader{})
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected no error while finishing new message, got:", err)
	}
	if !strings.Contains(s.transactionEvidenceLocked(), "<after-abort@example.org>") {
		t.Errorf("Expected report evidence for the new message, got %q", s.transactionEvidenceLocked())
	}
}

func TestTransactionRegressionCommittedRetryReplays(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	body := "same body\r\n"
	writeDKIMTransactionTestMessage(t, s, "<replay@example.org>", "Replay", body, textproto.MIMEHeader{})
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected no error while committing first message, got:", err)
	}

	firstSignature := s.signer.Signature()
	firstReport := s.transactionCommitRecords["<replay@example.org>"].report
	firstGeneration := s.generation

	writeDKIMTransactionTestMessage(t, s, "<replay@example.org>", "Replay", body, textproto.MIMEHeader{})
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected no error while replaying message, got:", err)
	}

	replayed := s.transactionCommitRecords["<replay@example.org>"]
	if replayed.signatureName == "" || replayed.signatureValue == "" {
		t.Fatal("Expected the replay to retain the original signature")
	}
	if got := replayed.signatureName + ": " + replayed.signatureValue + "\r\n"; got != firstSignature {
		t.Errorf("Expected replayed signature to be %q, got %q", firstSignature, got)
	}
	if replayed.report != firstReport {
		t.Errorf("Expected replayed report to be %q, got %q", firstReport, replayed.report)
	}
	if s.generation == firstGeneration {
		t.Error("Expected a new attempt generation while keeping the committed transaction")
	}
}

func TestTransactionRegressionMessageIDConflictRejected(t *testing.T) {
	s, cleanup := newDKIMTransactionTestSession(t)
	defer cleanup()

	writeDKIMTransactionTestMessage(t, s, "<conflict@example.org>", "Original", "original body\r\n", textproto.MIMEHeader{})
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected no error while committing first message, got:", err)
	}
	firstReport := s.transactionCommitRecords["<conflict@example.org>"].report

	writeDKIMTransactionTestMessage(t, s, "<conflict@example.org>", "Replacement", "replacement body\r\n", textproto.MIMEHeader{})
	if _, err := s.Body(nil); err == nil {
		t.Fatal("Expected a retry with different content under the same message ID to be rejected")
	}
	if s.stage != "message-id-conflict" {
		t.Errorf("Expected conflict stage, got %q", s.stage)
	}
	if s.committed {
		t.Error("Expected the conflicting message not to be committed")
	}
	if got := s.transactionCommitRecords["<conflict@example.org>"].report; got != firstReport {
		t.Errorf("Expected the original transaction to be retained, got %q", got)
	}
}
