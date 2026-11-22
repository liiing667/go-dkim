package dkim

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"strings"
)

// Status is the result of one DKIM signature check or of a whole message.
type Status string

const (
	// StatusNone means that the message didn't contain any DKIM-Signature
	// header field.
	StatusNone Status = "none"
	// StatusPass means that the signature (or every signature of a message)
	// verified successfully.
	StatusPass Status = "pass"
	// StatusFail means that the message was well-formed but the signature
	// didn't match the message contents.
	StatusFail Status = "fail"
	// StatusTempError means that verification couldn't complete because of a
	// temporary condition, for instance an unavailable DNS server.
	StatusTempError Status = "temperror"
	// StatusPermError means that verification failed permanently, for
	// instance because the signature is malformed or the key was revoked.
	StatusPermError Status = "permerror"
	// StatusError means that verification failed for an unclassified reason.
	StatusError Status = "error"
)

// DNSStatus describes the outcome of the public key lookup for one
// signature. It is kept separate from Status so a caller can distinguish a
// message failure from an unavailable or revoked DNS key.
type DNSStatus string

const (
	// DNSNotQueried means that no public key query was made, for instance
	// because the signature was malformed before the key lookup stage.
	DNSNotQueried DNSStatus = "not-queried"
	// DNSOK means that a public key was retrieved and parsed successfully.
	DNSOK DNSStatus = "ok"
	// DNSTempError means that the key lookup failed temporarily.
	DNSTempError DNSStatus = "temperror"
	// DNSPermError means that the key lookup or key record was permanently
	// invalid.
	DNSPermError DNSStatus = "permerror"
	// DNSRevoked means that the key record exists but its "p=" tag is empty.
	DNSRevoked DNSStatus = "revoked"
	// DNSUnclassified means that the key lookup failed for an unclassified
	// reason.
	DNSUnclassified DNSStatus = "error"
)

// StatusForError classifies a verification error using the same categories
// as the historical IsPermFail, IsTempFail and signature-failure helpers.
func StatusForError(err error) Status {
	switch {
	case err == nil:
		return StatusPass
	case IsTempFail(err):
		return StatusTempError
	case IsPermFail(err):
		return StatusPermError
	case isFail(err):
		return StatusFail
	default:
		return StatusError
	}
}

func dnsStatusForError(err error) DNSStatus {
	if err == nil {
		return DNSOK
	}
	if IsKeyRevoked(err) {
		return DNSRevoked
	}
	switch {
	case IsTempFail(err):
		return DNSTempError
	case IsPermFail(err):
		return DNSPermError
	default:
		return DNSUnclassified
	}
}

// SignatureReport is the immutable result of checking one DKIM-Signature
// header field. Index preserves the signature order in the accepted message.
type SignatureReport struct {
	// Index is the zero-based position of the signature in the message
	// header. Signatures are listed from the top of the header to the bottom.
	Index int `json:"index"`

	// Domain is the SDID ("d=") claimed by this signature. It is captured
	// when the message is accepted, before any DNS query is made.
	Domain string `json:"domain,omitempty"`
	// Selector is the selector ("s=") claimed by this signature.
	Selector string `json:"selector,omitempty"`
	// Identifier is the AUID ("i=") of this signature, if any.
	Identifier string `json:"identifier,omitempty"`

	// DNSStatus is the result of the public key lookup for this signature.
	DNSStatus DNSStatus `json:"dnsStatus"`
	// Result is the final outcome of this signature. It is never folded into
	// another signature's result.
	Result Status `json:"result"`
	// Error contains the human-readable verification error, if any.
	Error string `json:"error,omitempty"`

	// HeaderKeys lists the "h=" tag of this signature.
	HeaderKeys []string `json:"headerKeys,omitempty"`
	// BodyLength is the "l=" tag, or -1 when the whole body is signed.
	BodyLength int64 `json:"bodyLength"`
	// SignedAt is the "t=" tag as a Unix timestamp. Zero means absent.
	SignedAt int64 `json:"signedAt,omitempty"`
	// ExpiresAt is the "x=" tag as a Unix timestamp. Zero means absent.
	ExpiresAt int64 `json:"expiresAt,omitempty"`

	// headerIndex is the physical header position used to bind this report
	// to exactly one signature header during verification.
	headerIndex int
}

// MessageReport is the complete, ordered verification record of one message.
// Every signature keeps its own result and the message-level Conclusion is
// derived from that same ordered list.
type MessageReport struct {
	// Version is the report format version.
	Version int `json:"version"`
	// ID is a stable identifier of the exact message bytes.
	ID string `json:"id"`
	// Conclusion is the aggregate result for the message. It is only
	// StatusPass when every signature passed, and StatusNone when the message
	// has no signatures.
	Conclusion Status `json:"conclusion"`
	// Signatures contains one entry per DKIM-Signature header field, in the
	// order the fields appear in the message header.
	Signatures []*SignatureReport `json:"signatures"`
}

// Trusted reports whether every signature of the message passed. A message
// without any signature is not trusted.
func (r *MessageReport) Trusted() bool {
	return r != nil && len(r.Signatures) > 0 && r.FinalStatus() == StatusPass
}

// SignatureCount returns the number of signatures captured at acceptance.
func (r *MessageReport) SignatureCount() int {
	if r == nil {
		return 0
	}
	return len(r.Signatures)
}

// FinalStatus recomputes the message conclusion from the ordered signature
// list. Consumers that print the list and choose an exit status can use this
// one method for both, so a stale serialized conclusion cannot disagree with
// the signatures that were actually retained.
func (r *MessageReport) FinalStatus() Status {
	if r == nil {
		return StatusNone
	}
	return conclusionFor(r.Signatures)
}

func statusRank(s Status) int {
	switch s {
	case StatusPermError:
		return 5
	case StatusError:
		return 4
	case StatusFail:
		return 3
	case StatusTempError:
		return 2
	case StatusPass:
		return 1
	default:
		return 0
	}
}

func conclusionFor(signatures []*SignatureReport) Status {
	if len(signatures) == 0 {
		return StatusNone
	}

	conclusion := StatusPass
	for _, sig := range signatures {
		if sig == nil {
			continue
		}
		if statusRank(sig.Result) > statusRank(conclusion) {
			conclusion = sig.Result
		}
	}
	return conclusion
}

func (r *MessageReport) normalize() {
	if r == nil {
		return
	}
	if r.Version == 0 {
		r.Version = ManifestVersion
	}
	if r.Signatures == nil {
		r.Signatures = make([]*SignatureReport, 0)
	}
	// The conclusion is always derived from the ordered signature list, so a
	// loaded or externally supplied report cannot claim pass while retaining
	// a failed signature.
	r.Conclusion = r.FinalStatus()
}

// OverallStatus derives a message-level conclusion from the historical
// per-signature Verification list. It lets callers of Verify use the same
// non-folding rule as VerifyMessage: the result is only StatusPass when every
// signature passed, and StatusNone when the message had no signatures.
func OverallStatus(verifications []*Verification) Status {
	if len(verifications) == 0 {
		return StatusNone
	}

	conclusion := StatusPass
	for _, verif := range verifications {
		if verif == nil {
			continue
		}
		status := StatusForError(verif.Err)
		if statusRank(status) > statusRank(conclusion) {
			conclusion = status
		}
	}
	return conclusion
}

func messageID(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func signatureIdentity(value string) (domain, selector string) {
	params, err := parseHeaderParams(value)
	if err != nil {
		return "", ""
	}
	return stripWhitespace(params["d"]), stripWhitespace(params["s"])
}

type signatureSnapshot struct {
	headerIndex int
	raw         string
	domain      string
	selector    string
}

// VerifyMessage verifies every DKIM-Signature header field of a message and
// returns one ordered report for the whole message. The header and body are
// read once: all signature header fields, their claimed domains and their
// order are frozen before the first DNS query or signature check. A failure of
// one signature therefore cannot consume data needed by another signature or
// change the message-level conclusion into a misleading pass.
//
// Unlike Verify, VerifyMessage always consumes r completely. Verify is kept
// unchanged for callers that rely on its historical API and return values.
func VerifyMessage(r io.Reader) (*MessageReport, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	bufr := bufio.NewReader(bytes.NewReader(data))
	h, err := readHeader(bufr)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(bufr)
	if err != nil {
		return nil, err
	}

	report := &MessageReport{
		Version:    ManifestVersion,
		ID:         messageID(data),
		Signatures: make([]*SignatureReport, 0),
	}

	// Freeze every signature header, its claimed domain/selector and its
	// position before checking the first signature.
	snapshots := make([]signatureSnapshot, 0)
	for i, kv := range h {
		k, v := parseHeaderField(kv)
		if !strings.EqualFold(k, headerFieldName) {
			continue
		}
		domain, selector := signatureIdentity(v)
		snapshots = append(snapshots, signatureSnapshot{
			headerIndex: i,
			raw:         v,
			domain:      domain,
			selector:    selector,
		})
	}

	for i, snap := range snapshots {
		trace := new(verificationTrace)
		verif, verr := verifyWithTrace(h, bytes.NewReader(body), h[snap.headerIndex], snap.raw, trace)

		sig := &SignatureReport{
			Index:       i,
			Domain:      snap.domain,
			Selector:    snap.selector,
			DNSStatus:   trace.DNSStatus,
			Result:      StatusForError(verr),
			headerIndex: snap.headerIndex,
		}
		if verr != nil {
			sig.Error = verr.Error()
		}
		if verif != nil {
			sig.Identifier = verif.Identifier
			sig.HeaderKeys = append([]string(nil), verif.HeaderKeys...)
			sig.BodyLength = verif.BodyLength
			if !verif.Time.IsZero() {
				sig.SignedAt = verif.Time.Unix()
			}
			if !verif.Expiration.IsZero() {
				sig.ExpiresAt = verif.Expiration.Unix()
			}
		}
		report.Signatures = append(report.Signatures, sig)
	}

	report.Conclusion = report.FinalStatus()
	return report, nil
}
