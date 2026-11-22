package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/textproto"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth"
)

func newLocalMilterTxnSession(t *testing.T) (*session, func()) {
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

func addLocalMilterTxnHeader(t *testing.T, s *session, h textproto.MIMEHeader, name, value string) {
	t.Helper()

	if _, err := s.Header(name, value, nil); err != nil {
		t.Fatalf("Failed to write %v header: %v", name, err)
	}
	h[name] = append(h[name], value)
}

func writeLocalMilterTxnHeaders(t *testing.T, s *session, messageID, subject string, h textproto.MIMEHeader) {
	t.Helper()

	addLocalMilterTxnHeader(t, s, h, "From", "Joe SixPack <joe@example.org>")
	addLocalMilterTxnHeader(t, s, h, "To", "Suzie Q <suzie@example.net>")
	addLocalMilterTxnHeader(t, s, h, "Subject", subject)
	addLocalMilterTxnHeader(t, s, h, "Date", "Fri, 11 Jul 2003 21:00:37 -0700 (PDT)")
	addLocalMilterTxnHeader(t, s, h, "Message-ID", messageID)
}

func writeLocalMilterTxnMessage(t *testing.T, s *session, messageID, subject, body string, h textproto.MIMEHeader) {
	t.Helper()

	writeLocalMilterTxnHeaders(t, s, messageID, subject, h)
	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte(body), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
}

func localMilterTxnSignatureTag(t *testing.T, sig, tag string) string {
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

func localMilterTxnBodyDigest(body string) (string, string) {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:])
}

func TestLocalMilterTransactionUnsignedMailPreservesExistingResults(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	oldSignDomains := signDomains
	signDomains = nil
	defer func() { signDomains = oldSignDomains }()

	body := "Hello, unsigned world!\r\n"
	messageID := "<unsigned@example.org>"
	h := textproto.MIMEHeader{}

	writeLocalMilterTxnHeaders(t, s, messageID, "Unsigned", h)
	addLocalMilterTxnHeader(t, s, h, "Authentication-Results", "other.example; dkim=pass header.d=other.example")
	addLocalMilterTxnHeader(t, s, h, "Authentication-Results", identity+"; dkim=fail header.d=old.example")

	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte(body), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
	resp, err := s.Body(nil)
	if err != nil {
		t.Fatal("Expected unsigned message to be accepted, got:", err)
	}
	if resp == nil {
		t.Error("Expected an accept response")
	}
	if s.signer != nil {
		t.Error("Expected unsigned mail not to create a signer")
	}

	// Only our own Authentication-Results field may be replaced. In the
	// complete header block it is the seventh field (index 6); the result
	// belonging to another authserv-id must stay untouched.
	if len(s.authResDelete) != 1 || s.authResDelete[0] != 6 {
		t.Errorf("Expected only our Authentication-Results at absolute index 6, got %v", s.authResDelete)
	}

	results := s.authResultsLocked()
	if len(results) != 1 {
		t.Fatalf("Expected one unsigned DKIM result, got %v", len(results))
	}
	dkimResult, ok := results[0].(*msgauth.DKIMResult)
	if !ok {
		t.Fatalf("Expected a DKIM result, got %T", results[0])
	}
	if dkimResult.Value != msgauth.ResultNone {
		t.Errorf("Expected dkim=none, got %v", dkimResult.Value)
	}

	record := s.transactionCommitRecords[messageID]
	if record == nil {
		t.Fatal("Expected a committed transaction record")
	}
	bodyHex, _ := localMilterTxnBodyDigest(body)
	for _, want := range []string{"dkim=none", messageID, s.headerDigest, bodyHex, "stage=commit", "generation="} {
		if !strings.Contains(record.report, want) {
			t.Errorf("Expected report to contain %q, got %q", want, record.report)
		}
	}
	if strings.Contains(record.report, "old.example") {
		t.Errorf("Expected the stale result to be replaced, got %q", record.report)
	}
}

func TestLocalMilterTransactionAuthResUsesHeaderCallbackSnapshot(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	oldSignDomains := signDomains
	signDomains = nil
	defer func() { signDomains = oldSignDomains }()

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnHeaders(t, s, "<authres-callbacks@example.org>", "AuthRes callbacks", h)
	addLocalMilterTxnHeader(t, s, h, "Authentication-Results", "other.example; dkim=pass")
	addLocalMilterTxnHeader(t, s, h, "Authentication-Results", identity+"; dkim=fail")

	// Some milter callers only provide the fields they inspect in the final
	// map. The absolute deletion index must still come from the Header
	// callback snapshot.
	if _, err := s.Headers(textproto.MIMEHeader{}, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte("body\r\n"), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected message to be accepted, got:", err)
	}
	if len(s.authResDelete) != 1 || s.authResDelete[0] != 6 {
		t.Errorf("Expected our Authentication-Results at absolute index 6, got %v", s.authResDelete)
	}
}

func TestLocalMilterTransactionBodyFailureDoesNotLeakIntoSameIDRetry(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	messageID := "<retry-same-id@example.org>"
	oldBody := "old body\r\n"
	oldBodyHex, _ := localMilterTxnBodyDigest(oldBody)

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnHeaders(t, s, messageID, "Old subject", h)
	addLocalMilterTxnHeader(t, s, h, "Authentication-Results", identity+"; dkim=pass header.d=old.example")
	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte(oldBody), nil); err != nil {
		t.Fatal("Failed to write old body:", err)
	}

	// Simulate a body-stage failure: the verification stream is broken after
	// the first message already consumed part of its body.
	s.pw.CloseWithError(errors.New("synthetic body-stage failure"))
	if _, err := s.BodyChunk([]byte("partial\r\n"), nil); err == nil {
		t.Fatal("Expected a body-stage error")
	}

	if s.signer != nil || s.pw != nil || s.verifs != nil || s.authResDelete != nil {
		t.Fatalf("Expected failed transaction state to be discarded, got signer=%v pw=%v verifs=%v authResDelete=%v",
			s.signer, s.pw, s.verifs, s.authResDelete)
	}
	if s.active {
		t.Error("Expected failed transaction to be inactive")
	}

	// Retrying the same SMTP Message-ID must start a completely new snapshot
	// and sign only the new body. It must not inherit the old body, signer,
	// verification result or pending header deletion.
	newBody := "new body\r\n"
	h = textproto.MIMEHeader{}
	writeLocalMilterTxnHeaders(t, s, messageID, "New subject", h)
	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish retry headers:", err)
	}
	if _, err := s.BodyChunk([]byte(newBody), nil); err != nil {
		t.Fatal("Failed to write retry body:", err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected retried message to commit, got:", err)
	}

	if s.bodyLen != int64(len(newBody)) {
		t.Errorf("Expected body length %v, got %v", len(newBody), s.bodyLen)
	}
	_, wantBodyHash := localMilterTxnBodyDigest(newBody)
	if got := localMilterTxnSignatureTag(t, s.signer.Signature(), "bh"); got != wantBodyHash {
		t.Errorf("Expected retried body hash %q, got %q", wantBodyHash, got)
	}

	record := s.transactionCommitRecords[messageID]
	if record == nil {
		t.Fatal("Expected retried message to be committed")
	}
	newBodyHex, _ := localMilterTxnBodyDigest(newBody)
	if !strings.Contains(record.report, newBodyHex) {
		t.Errorf("Expected report to contain current body digest %q, got %q", newBodyHex, record.report)
	}
	if strings.Contains(record.report, oldBodyHex) {
		t.Errorf("Expected report not to contain old body digest %q, got %q", oldBodyHex, record.report)
	}
	if !strings.Contains(record.report, messageID) {
		t.Errorf("Expected report to contain current Message-ID %q, got %q", messageID, record.report)
	}
}

func TestLocalMilterTransactionVerifyFailureFailsClosedAndResets(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	oldSignDomains := signDomains
	signDomains = nil
	defer func() { signDomains = oldSignDomains }()

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnHeaders(t, s, "<verify-failure@example.org>", "Verify failure", h)
	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte("body\r\n"), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}

	// Force the verifier outcome to fail even though the message bytes were
	// accepted. Body must reject the whole transaction and clear its state.
	s.verifyDone = make(chan transactionVerifyOutcome, 1)
	s.verifyDone <- transactionVerifyOutcome{err: errors.New("synthetic verify failure")}
	if _, err := s.Body(nil); err == nil {
		t.Fatal("Expected verification failure to reject the message")
	}
	if s.active || s.committed || s.authResDelete != nil || s.verifs != nil {
		t.Fatalf("Expected failed verification to leave no committed state, got active=%v committed=%v authResDelete=%v verifs=%v",
			s.active, s.committed, s.authResDelete, s.verifs)
	}

	signDomains = oldSignDomains
	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<after-verify-failure@example.org>", "After failure", "clean body\r\n", h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected a clean message after verification failure, got:", err)
	}
	if !strings.Contains(s.transactionEvidenceLocked(), "<after-verify-failure@example.org>") {
		t.Errorf("Expected evidence for the new message, got %q", s.transactionEvidenceLocked())
	}
}

func TestLocalMilterTransactionMultipleRecipientsAndEmptyBodyRetry(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	if _, err := s.MailFrom("<joe@example.org>", nil); err != nil {
		t.Fatal("Failed to start envelope:", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.RcptTo("<rcpt@example.net>", nil); err != nil {
			t.Fatal("Failed to add recipient:", err)
		}
	}

	firstBody := "first body\r\n"
	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<first@example.org>", "First", firstBody, h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected first message to commit, got:", err)
	}
	firstGeneration := s.generation
	firstRecord := s.transactionCommitRecords["<first@example.org>"]
	if firstRecord == nil {
		t.Fatal("Expected a first transaction record")
	}

	// Recipients alone never reset a message transaction. Additional
	// recipients must not start a second generation.
	for i := 0; i < 3; i++ {
		if _, err := s.RcptTo("<rcpt@example.net>", nil); err != nil {
			t.Fatal("Failed to add next recipient:", err)
		}
	}
	if s.generation != firstGeneration {
		t.Fatalf("Expected recipients not to change generation, got %v -> %v", firstGeneration, s.generation)
	}

	// The retry deliberately omits BodyChunk. It must sign an empty body, not
	// reuse the previous message's body bytes.
	h = textproto.MIMEHeader{}
	writeLocalMilterTxnHeaders(t, s, "<second@example.org>", "Second", h)
	if s.generation != firstGeneration+1 {
		t.Fatalf("Expected exactly one new generation, got %v -> %v", firstGeneration, s.generation)
	}
	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish second headers:", err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected second message to commit, got:", err)
	}
	if s.bodyLen != 0 {
		t.Errorf("Expected empty body, got %v bytes", s.bodyLen)
	}

	// DKIM simple body canonicalization represents an empty body as CRLF.
	emptyBodyHash := "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
	if got := localMilterTxnSignatureTag(t, s.signer.Signature(), "bh"); got != emptyBodyHash {
		t.Errorf("Expected empty body hash %q, got %q", emptyBodyHash, got)
	}

	secondRecord := s.transactionCommitRecords["<second@example.org>"]
	if secondRecord == nil {
		t.Fatal("Expected a second transaction record")
	}
	if !strings.Contains(secondRecord.report, "<second@example.org>") {
		t.Errorf("Expected second report to contain its Message-ID, got %q", secondRecord.report)
	}
	if strings.Contains(secondRecord.report, "<first@example.org>") {
		t.Errorf("Expected second report not to contain the first Message-ID, got %q", secondRecord.report)
	}
	firstBodyHex, _ := localMilterTxnBodyDigest(firstBody)
	if strings.Contains(secondRecord.report, firstBodyHex) {
		t.Errorf("Expected second report not to contain the first body digest, got %q", secondRecord.report)
	}
}

func TestLocalMilterTransactionMultipleRecipientHeaders(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	h := textproto.MIMEHeader{}
	addLocalMilterTxnHeader(t, s, h, "From", "Joe SixPack <joe@example.org>")
	addLocalMilterTxnHeader(t, s, h, "To", "Suzie Q <suzie@example.net>")
	addLocalMilterTxnHeader(t, s, h, "To", "Alice <alice@example.net>")
	addLocalMilterTxnHeader(t, s, h, "Subject", "Multiple recipients")
	addLocalMilterTxnHeader(t, s, h, "Date", "Fri, 11 Jul 2003 21:00:37 -0700 (PDT)")
	addLocalMilterTxnHeader(t, s, h, "Message-ID", "<multi-recipient@example.org>")

	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte("body\r\n"), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected multi-recipient message to be accepted, got:", err)
	}

	toCount := 0
	for _, name := range s.signHeaderKeys {
		if strings.EqualFold(name, "To") {
			toCount++
		}
	}
	if toCount != 2 {
		t.Errorf("Expected both To header fields to be signed, got %v in %v", toCount, s.signHeaderKeys)
	}
	if !strings.Contains(s.transactionEvidenceLocked(), "<multi-recipient@example.org>") {
		t.Errorf("Expected evidence for multi-recipient message, got %q", s.transactionEvidenceLocked())
	}
}

func TestLocalMilterTransactionEmptySignatureHeaderStillCommits(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	h := textproto.MIMEHeader{}
	addLocalMilterTxnHeader(t, s, h, "From", "Joe SixPack <joe@example.org>")
	addLocalMilterTxnHeader(t, s, h, "Message-ID", "<empty-signature@example.org>")
	addLocalMilterTxnHeader(t, s, h, "DKIM-Signature", "")
	addLocalMilterTxnHeader(t, s, h, "Subject", "Empty signature")

	if _, err := s.Headers(h, nil); err != nil {
		t.Fatal("Failed to finish headers:", err)
	}
	if _, err := s.BodyChunk([]byte("body\r\n"), nil); err != nil {
		t.Fatal("Failed to write body:", err)
	}
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected empty signature header to be accepted, got:", err)
	}
	if len(s.verifs) != 1 {
		t.Fatalf("Expected one verification, got %v", len(s.verifs))
	}
	if s.verifs[0].Err == nil {
		t.Error("Expected the empty signature to fail verification")
	}
	if s.signer == nil || s.signer.Signature() == "" {
		t.Error("Expected the message to be signed")
	}

	results := s.authResultsLocked()
	if len(results) != 1 {
		t.Fatalf("Expected one DKIM result, got %v", len(results))
	}
	dkimResult, ok := results[0].(*msgauth.DKIMResult)
	if !ok {
		t.Fatalf("Expected a DKIM result, got %T", results[0])
	}
	if dkimResult.Value == msgauth.ResultNone || dkimResult.Value == msgauth.ResultPass {
		t.Errorf("Expected a failure result for the empty signature, got %v", dkimResult.Value)
	}
}

func TestLocalMilterTransactionAbortCancelsBackgroundWork(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<abort@example.org>", "Abort", "partial body\r\n", h)

	s.Abort()
	if s.active {
		t.Error("Expected aborted session to be inactive")
	}
	if s.signer != nil || s.pw != nil || s.verifs != nil || s.authResDelete != nil {
		t.Fatalf("Expected abort to discard all message state, got signer=%v pw=%v verifs=%v authResDelete=%v",
			s.signer, s.pw, s.verifs, s.authResDelete)
	}

	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<after-abort@example.org>", "After abort", "complete body\r\n", h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected a clean message after abort, got:", err)
	}
	if !strings.Contains(s.transactionEvidenceLocked(), "<after-abort@example.org>") {
		t.Errorf("Expected evidence for the new message, got %q", s.transactionEvidenceLocked())
	}
}

func TestLocalMilterTransactionCommittedRetryReplaysAndConflictRejected(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	body := "same body\r\n"
	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<replay@example.org>", "Replay", body, h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected first message to commit, got:", err)
	}

	firstSignature := s.signer.Signature()
	firstCommitted := s.transactionCommitRecords["<replay@example.org>"]
	if firstCommitted == nil {
		t.Fatal("Expected the first message to have a committed record")
	}
	firstRecord := *firstCommitted
	firstGeneration := s.generation

	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<replay@example.org>", "Replay", body, h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected identical retry to replay, got:", err)
	}

	replayed := s.transactionCommitRecords["<replay@example.org>"]
	if replayed.signatureName == "" || replayed.signatureValue == "" {
		t.Fatal("Expected the replay to retain the original signature")
	}
	if got := replayed.signatureName + ": " + replayed.signatureValue + "\r\n"; got != firstSignature {
		t.Errorf("Expected replayed signature %q, got %q", firstSignature, got)
	}
	if replayed.report != firstRecord.report {
		t.Errorf("Expected replayed report %q, got %q", firstRecord.report, replayed.report)
	}
	if s.generation == firstGeneration {
		t.Error("Expected a new attempt generation while keeping the committed transaction")
	}

	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<replay@example.org>", "Different content", "different body\r\n", h)
	if _, err := s.Body(nil); err == nil {
		t.Fatal("Expected a changed retry under the same Message-ID to be rejected")
	}
	if s.stage != "message-id-conflict" {
		t.Errorf("Expected conflict stage, got %q", s.stage)
	}
	if s.committed {
		t.Error("Expected the conflicting message not to be committed")
	}
	if got := s.transactionCommitRecords["<replay@example.org>"].report; got != firstRecord.report {
		t.Errorf("Expected the original transaction to be retained, got %q", got)
	}
}

func TestLocalMilterTransactionEvidenceIsSameSourcePerMessage(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	firstBody := "first body\r\n"
	secondBody := "second body\r\n"
	firstID := "<evidence-one@example.org>"
	secondID := "<evidence-two@example.org>"

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, firstID, "Evidence one", firstBody, h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected first message to commit, got:", err)
	}
	first := s.transactionCommitRecords[firstID]
	if first == nil {
		t.Fatal("Expected first transaction record")
	}
	firstBodyHex, _ := localMilterTxnBodyDigest(firstBody)

	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, secondID, "Evidence two", secondBody, h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected second message to commit, got:", err)
	}
	second := s.transactionCommitRecords[secondID]
	if second == nil {
		t.Fatal("Expected second transaction record")
	}
	secondBodyHex, _ := localMilterTxnBodyDigest(secondBody)

	for _, want := range []string{firstID, firstBodyHex, first.headerDigest, "stage=commit"} {
		if !strings.Contains(first.report, want) {
			t.Errorf("Expected first report to contain %q, got %q", want, first.report)
		}
	}
	for _, want := range []string{secondID, secondBodyHex, second.headerDigest, "stage=commit"} {
		if !strings.Contains(second.report, want) {
			t.Errorf("Expected second report to contain %q, got %q", want, second.report)
		}
	}
	if strings.Contains(second.report, firstID) || strings.Contains(second.report, firstBodyHex) {
		t.Errorf("Expected the second report to be sourced only from the second message, got %q", second.report)
	}
	if first.headerDigest == second.headerDigest {
		t.Error("Expected different messages to have different header digests")
	}
}

func TestLocalMilterTransactionRestartHasNoStateFromPreviousSession(t *testing.T) {
	firstSession, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	messageID := "<restart@example.org>"
	firstBody := "before restart\r\n"
	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, firstSession, messageID, "Before restart", firstBody, h)
	if _, err := firstSession.Body(nil); err != nil {
		t.Fatal("Expected first session to commit, got:", err)
	}
	firstBodyHex, _ := localMilterTxnBodyDigest(firstBody)

	// A process restart creates a new session. It must start from an empty
	// transaction history and sign only the message submitted to it.
	restarted := &session{}
	secondBody := "after restart\r\n"
	h = textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, restarted, messageID, "After restart", secondBody, h)
	if _, err := restarted.Body(nil); err != nil {
		t.Fatal("Expected the restarted session to accept the new message, got:", err)
	}

	record := restarted.transactionCommitRecords[messageID]
	if record == nil {
		t.Fatal("Expected the restarted session to commit the current message")
	}
	_, currentBodyHash := localMilterTxnBodyDigest(secondBody)
	if got := localMilterTxnSignatureTag(t, restarted.signer.Signature(), "bh"); got != currentBodyHash {
		t.Errorf("Expected restarted-session body hash %q, got %q", currentBodyHash, got)
	}
	secondBodyHex, _ := localMilterTxnBodyDigest(secondBody)
	if !strings.Contains(record.report, secondBodyHex) {
		t.Errorf("Expected report to contain the current body digest %q, got %q", secondBodyHex, record.report)
	}
	if strings.Contains(record.report, firstBodyHex) {
		t.Errorf("Expected restarted session not to contain the previous body digest %q, got %q", firstBodyHex, record.report)
	}
}

func TestLocalMilterTransactionHeaderErrorFailsClosed(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	if _, err := s.Header("From", "not an address", nil); err == nil {
		t.Fatal("Expected malformed From header to be rejected")
	}
	if s.active || s.signer != nil || s.pw != nil {
		t.Fatalf("Expected malformed header to fail closed, got active=%v signer=%v pw=%v", s.active, s.signer, s.pw)
	}

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<after-header-error@example.org>", "After header error", "body\r\n", h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected a clean message after a header error, got:", err)
	}
}

func TestLocalMilterTransactionDuplicateIdentityHeaderFailsClosed(t *testing.T) {
	s, cleanup := newLocalMilterTxnSession(t)
	defer cleanup()

	if _, err := s.Header("From", "Joe SixPack <joe@example.org>", nil); err != nil {
		t.Fatal("Failed to write first From header:", err)
	}
	if _, err := s.Header("From", "Mallory <mallory@example.net>", nil); err == nil {
		t.Fatal("Expected an ambiguous duplicate From header to be rejected")
	}
	if s.active || s.signer != nil || s.pw != nil {
		t.Fatalf("Expected duplicate identity header to fail closed, got active=%v signer=%v pw=%v",
			s.active, s.signer, s.pw)
	}
	if s.stage != "duplicate-header" {
		t.Errorf("Expected duplicate-header stage, got %q", s.stage)
	}

	h := textproto.MIMEHeader{}
	writeLocalMilterTxnMessage(t, s, "<after-duplicate@example.org>", "After duplicate", "body\r\n", h)
	if _, err := s.Body(nil); err != nil {
		t.Fatal("Expected a clean message after duplicate header rejection, got:", err)
	}
}
