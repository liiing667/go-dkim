package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type permFailError string

func (err permFailError) Error() string {
	return "dkim: " + string(err)
}

// IsPermFail returns true if the error returned by Verify is a permanent
// failure. A permanent failure is for instance a missing required field or a
// malformed header.
func IsPermFail(err error) bool {
	for err != nil {
		if _, ok := err.(permFailError); ok {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dkim: " + string(err)
}

// IsTempFail returns true if the error returned by Verify is a temporary
// failure.
func IsTempFail(err error) bool {
	for err != nil {
		if _, ok := err.(tempFailError); ok {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

type failError string

func (err failError) Error() string {
	return "dkim: " + string(err)
}

// isFail returns true if the error returned by Verify is a signature error.
func isFail(err error) bool {
	for err != nil {
		if _, ok := err.(failError); ok {
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

// VerificationStage identifies a stage of the DKIM verification pipeline.
type VerificationStage string

const (
	// VerificationStageParse is the signature parsing/validation stage.
	VerificationStageParse VerificationStage = "parse"
	// VerificationStageKeyQuery is the public key DNS query stage.
	VerificationStageKeyQuery VerificationStage = "key-query"
	// VerificationStageBodyHash is the body hash verification stage ("bh=").
	VerificationStageBodyHash VerificationStage = "body-hash"
	// VerificationStageHeaderHash is the signed header data hashing stage.
	VerificationStageHeaderHash VerificationStage = "header-hash"
	// VerificationStageCryptoVerify is the public-key signature check stage.
	VerificationStageCryptoVerify VerificationStage = "crypto-verify"
)

// stageError carries a verification stage without changing the concrete error
// type returned to callers. IsPermFail, IsTempFail and isFail keep working on
// the original error stored in Cause.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *stageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (e *stageError) Stage() string {
	if e == nil {
		return ""
	}
	return e.stage
}

func (e *stageError) Cause() error {
	if e == nil {
		return nil
	}
	return e.err
}

func newStageError(stage VerificationStage, err error) error {
	if err == nil {
		return nil
	}
	return &stageError{stage: string(stage), err: err}
}

// ErrorStage returns the verification stage recorded on a report error. The
// error returned to the caller is left unchanged; only VerifyReport.Err is
// wrapped with its stage.
func ErrorStage(err error) string {
	for err != nil {
		if se, ok := err.(*stageError); ok {
			return se.stage
		}
		if se, ok := err.(interface{ Stage() string }); ok {
			return se.Stage()
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ""
		}
		err = unwrapper.Unwrap()
	}
	return ""
}

// VerifyOptions configures VerifyWithOptions.
type VerifyOptions struct {
	// Reports, if true, attaches a detailed VerifyReport to each returned
	// Verification and fills the selector/key metadata fields.
	Reports bool
	// KeyCache is the DNS public-key cache to use. If nil, the process-wide
	// DefaultKeyCache is used.
	KeyCache *KeyCache
	// Cache is an alias for KeyCache.
	Cache *KeyCache
}

// VerifyReport describes the verification of one DKIM-Signature header field.
// It retains the identity that was frozen at the start of verification: the
// domain, selector, key generation and key fingerprint.
type VerifyReport struct {
	// Domain is the SDID claimed by the signature ("d=").
	Domain string
	// Selector is the selector claimed by the signature ("s=").
	Selector string
	// KeyGeneration is the cache generation frozen for this verification.
	KeyGeneration uint64
	// KeyFingerprint is the SHA-256 fingerprint (hex) of the public key.
	KeyFingerprint string
	// KeyDigest is an alias for KeyFingerprint.
	KeyDigest string
	// CacheSource is "dns" when the key was fetched during this verification
	// and "cache" when it was served from a committed cache entry.
	CacheSource string
	// Source is the typed form of CacheSource.
	Source KeySource
	// Key is the immutable key snapshot frozen for this verification.
	Key *Key

	// BodyDigest is the base64-encoded canonicalized body hash computed by
	// this verification.
	BodyDigest string
	// HeaderDigest is the base64-encoded hash of the signed header data.
	HeaderDigest string

	// Stage is the pipeline stage the verification reached. On failure it is
	// the failing stage.
	Stage VerificationStage
	// Err is the failure with its stage recorded. It is nil on success.
	Err error
	// Cause is the original failure before the stage was attached.
	Cause error
}

// VerificationReport is an alias for VerifyReport.
type VerificationReport = VerifyReport

func (r *VerifyReport) setStage(stage VerificationStage) {
	if r != nil {
		r.Stage = stage
	}
}

func (r *VerifyReport) fail(stage VerificationStage, err error) error {
	if r != nil {
		r.Stage = stage
		r.Cause = err
		r.Err = newStageError(stage, err)
	}
	return err
}

var requiredTags = []string{"v", "a", "b", "bh", "d", "h", "s"}

// A Verification is produced by Verify when it checks if one signature is
// valid. If the signature is valid, Err is nil.
type Verification struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream.
	Domain string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	Identifier string

	// The list of signed header fields.
	HeaderKeys []string
	// The number of bytes in the body which are signed. If the whole body is
	// signed, BodyLength is < 0.
	BodyLength int64

	// The time that this signature was created. If unknown, it's set to zero.
	Time time.Time
	// The expiration time. If the signature doesn't expire, it's set to zero.
	Expiration time.Time

	// Selector is the selector ("s=") claimed by the signature. It is filled
	// when verification reports are enabled.
	Selector string
	// KeyGeneration is the cache generation frozen for this verification. It
	// is filled when verification reports are enabled.
	KeyGeneration uint64
	// KeyFingerprint is the fingerprint of the frozen public key. It is filled
	// when verification reports are enabled.
	KeyFingerprint string
	// KeyDigest is an alias for KeyFingerprint.
	KeyDigest string
	// CacheSource says whether the key came from DNS or the cache. It is filled
	// when verification reports are enabled.
	CacheSource string
	// Source is the typed form of CacheSource.
	Source KeySource
	// Key is the immutable public-key snapshot frozen for this verification.
	// It is filled when verification reports are enabled.
	Key *Key
	// Stage is the verification stage reached. It is filled when verification
	// reports are enabled.
	Stage VerificationStage

	// Err is nil if the signature is valid.
	Err error

	// Report is the detailed verification report. It is only populated when
	// Verify is called through VerifyWithOptions with Reports enabled. Plain
	// Verify leaves it nil so existing Verification values keep comparing
	// equal.
	Report *VerifyReport
}

type signature struct {
	i int
	v string
}

// keyQueryError marks a failure while resolving the public key. It lets
// Verify report the failure on the affected signature without aborting other
// signatures or hiding the original error type.
type keyQueryError struct {
	cause error
}

func (e *keyQueryError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *keyQueryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Verify checks if a message's signatures are valid. It returns one
// verification per signature.
//
// There is no guarantee that the reader will be completely consumed.
func Verify(r io.Reader) ([]*Verification, error) {
	return VerifyWithOptions(r, nil)
}

// VerifyWithOptions behaves like Verify but allows selecting the DNS key cache
// and requesting detailed verification reports.
//
// Every signature freezes its domain, selector and key generation before the
// body is hashed. A rotation that happens afterwards cannot change the key
// used by this verification.
func VerifyWithOptions(r io.Reader, opts *VerifyOptions) ([]*Verification, error) {
	// TODO: be able to specify options such as the max number of signatures to
	// check

	withReports := opts != nil && opts.Reports
	collectMetadata := opts != nil && (opts.Reports || opts.KeyCache != nil || opts.Cache != nil)
	cache := defaultKeyCache
	if opts != nil && opts.KeyCache != nil {
		cache = opts.KeyCache
	} else if opts != nil && opts.Cache != nil {
		cache = opts.Cache
	}

	// Read header
	bufr := bufio.NewReader(r)
	h, err := readHeader(bufr)
	if err != nil {
		return nil, err
	}

	// Scan header fields for signatures
	var signatures []*signature
	for i, kv := range h {
		k, v := parseHeaderField(kv)
		if strings.EqualFold(k, headerFieldName) {
			signatures = append(signatures, &signature{i, v})
		}
	}

	// Copy body in a buffer if multiple signatures are checked
	var br *bytes.Reader
	if len(signatures) > 1 {
		b, err := ioutil.ReadAll(bufr)
		if err != nil {
			return nil, err
		}
		br = bytes.NewReader(b)
	}

	verifications := make([]*Verification, len(signatures))
	for i, sig := range signatures {
		// Use the bytes.Reader if there is one
		var r io.Reader = bufr
		if br != nil {
			br.Seek(0, io.SeekStart)
			r = br
		}

		var report *VerifyReport
		if collectMetadata {
			report = &VerifyReport{CacheSource: CacheSourceNone}
		}

		v, err := verifyWithOptions(h, r, h[sig.i], sig.v, cache, report)
		if err != nil && !IsTempFail(err) && !IsPermFail(err) && !isFail(err) {
			if _, ok := err.(*keyQueryError); !ok {
				if withReports && report != nil {
					v.Report = report
				}
				if collectMetadata && report != nil {
					v.Stage = report.Stage
				}
				v.Err = err
				verifications[i] = v
				return verifications, err
			}
		}

		if withReports && report != nil {
			v.Report = report
		}
		if collectMetadata && report != nil {
			v.Stage = report.Stage
		}
		if kq, ok := err.(*keyQueryError); ok {
			v.Err = kq.cause
		} else {
			v.Err = err
		}
		verifications[i] = v
	}
	return verifications, nil
}

func verify(h header, r io.Reader, sigField, sigValue string) (*Verification, error) {
	v, err := verifyWithOptions(h, r, sigField, sigValue, defaultKeyCache, nil)
	if kq, ok := err.(*keyQueryError); ok {
		return v, kq.cause
	}
	return v, err
}

func verifyWithOptions(h header, r io.Reader, sigField, sigValue string, cache *KeyCache, report *VerifyReport) (*Verification, error) {
	verif := new(Verification)
	if cache == nil {
		cache = defaultKeyCache
	}
	if report != nil {
		verif.CacheSource = CacheSourceNone
		verif.Source = KeySourceNone
	}
	report.setStage(VerificationStageParse)

	params, err := parseHeaderParams(sigValue)
	if err != nil {
		return verif, report.fail(VerificationStageParse, permFailError("malformed signature tags: "+err.Error()))
	}

	if params["v"] != "1" {
		return verif, report.fail(VerificationStageParse, permFailError("incompatible signature version"))
	}

	// Freeze the signature identity before any DNS lookup or body processing.
	// The same domain and selector are used for the whole verification.
	domain := stripWhitespace(params["d"])
	selector := stripWhitespace(params["s"])
	verif.Domain = domain
	if report != nil {
		report.Domain = domain
		report.Selector = selector
		verif.Selector = selector
	}

	for _, tag := range requiredTags {
		if _, ok := params[tag]; !ok {
			return verif, report.fail(VerificationStageParse, permFailError("signature missing required tag"))
		}
	}

	if i, ok := params["i"]; ok {
		verif.Identifier = stripWhitespace(i)
		if !strings.HasSuffix(verif.Identifier, "@"+verif.Domain) && !strings.HasSuffix(verif.Identifier, "."+verif.Domain) {
			return verif, report.fail(VerificationStageParse, permFailError("domain mismatch"))
		}
	} else {
		verif.Identifier = "@" + verif.Domain
	}

	headerKeys := parseTagList(params["h"])
	ok := false
	for _, k := range headerKeys {
		if strings.ToLower(k) == "from" {
			ok = true
			break
		}
	}
	if !ok {
		return verif, report.fail(VerificationStageParse, permFailError("From field not signed"))
	}
	verif.HeaderKeys = headerKeys

	if timeStr, ok := params["t"]; ok {
		t, err := parseTime(timeStr)
		if err != nil {
			return verif, report.fail(VerificationStageParse, permFailError("malformed time: "+err.Error()))
		}
		verif.Time = t
	}
	if expiresStr, ok := params["x"]; ok {
		t, err := parseTime(expiresStr)
		if err != nil {
			return verif, report.fail(VerificationStageParse, permFailError("malformed expiration time: "+err.Error()))
		}
		verif.Expiration = t
		if now().After(t) {
			return verif, report.fail(VerificationStageParse, permFailError("signature has expired"))
		}
	}

	// Query and freeze the public key. The frozen Key snapshot owns the
	// domain, selector, generation, fingerprint and verifier for the rest of
	// this verification. A later rotation cannot affect it.
	// TODO: compute hash in parallel
	methods := []string{string(QueryMethodDNSTXT)}
	if methodsStr, ok := params["q"]; ok {
		methods = parseTagList(methodsStr)
	}
	report.setStage(VerificationStageKeyQuery)
	frozenKey, err := cache.ResolveMethods(domain, selector, methods)
	if err != nil {
		report.fail(VerificationStageKeyQuery, err)
		return verif, &keyQueryError{cause: err}
	} else if frozenKey == nil {
		err = permFailError("no key for signature")
		report.fail(VerificationStageKeyQuery, err)
		return verif, &keyQueryError{cause: err}
	}
	if report != nil {
		verif.Selector = frozenKey.Selector
		verif.KeyGeneration = frozenKey.Generation
		verif.KeyFingerprint = frozenKey.Fingerprint
		verif.KeyDigest = frozenKey.Fingerprint
		verif.CacheSource = string(frozenKey.Source)
		verif.Source = frozenKey.Source
		verif.Key = frozenKey
		report.Domain = frozenKey.Domain
		report.Selector = frozenKey.Selector
		report.KeyGeneration = frozenKey.Generation
		report.KeyFingerprint = frozenKey.Fingerprint
		report.KeyDigest = frozenKey.Fingerprint
		report.CacheSource = string(frozenKey.Source)
		report.Source = frozenKey.Source
		report.Key = frozenKey
	}

	// Parse algos
	algos := strings.SplitN(stripWhitespace(params["a"]), "-", 2)
	if len(algos) != 2 {
		return verif, report.fail(VerificationStageParse, permFailError("malformed algorithm name"))
	}
	keyAlgo := algos[0]
	hashAlgo := algos[1]

	// Check hash algo
	if frozenKey.HashAlgos != nil {
		ok := false
		for _, algo := range frozenKey.HashAlgos {
			if algo == hashAlgo {
				ok = true
				break
			}
		}
		if !ok {
			return verif, report.fail(VerificationStageParse, permFailError("inappropriate hash algorithm"))
		}
	}
	var hash crypto.Hash
	switch hashAlgo {
	case "sha1":
		// RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for signing or
		// verifying.
		return verif, report.fail(VerificationStageParse, permFailError(fmt.Sprintf("hash algorithm too weak: %v", hashAlgo)))
	case "sha256":
		hash = crypto.SHA256
	default:
		return verif, report.fail(VerificationStageParse, permFailError("unsupported hash algorithm"))
	}

	// Check key algo
	if frozenKey.KeyAlgo != keyAlgo {
		return verif, report.fail(VerificationStageParse, permFailError("inappropriate key algorithm"))
	}

	if frozenKey.Services != nil {
		ok := false
		for _, s := range frozenKey.Services {
			if s == "email" {
				ok = true
				break
			}
		}
		if !ok {
			return verif, report.fail(VerificationStageParse, permFailError("inappropriate service"))
		}
	}

	headerCan, bodyCan := parseCanonicalization(params["c"])
	if _, ok := canonicalizers[headerCan]; !ok {
		return verif, report.fail(VerificationStageParse, permFailError("unsupported header canonicalization algorithm"))
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return verif, report.fail(VerificationStageParse, permFailError("unsupported body canonicalization algorithm"))
	}

	var bodyLen int64 = -1
	if lenStr, ok := params["l"]; ok {
		l, err := strconv.ParseInt(stripWhitespace(lenStr), 10, 64)
		if err != nil {
			return verif, report.fail(VerificationStageParse, permFailError("malformed body length: "+err.Error()))
		} else if l < 0 {
			return verif, report.fail(VerificationStageParse, permFailError("malformed body length: negative value"))
		}
		bodyLen = l
	}
	verif.BodyLength = bodyLen

	// Parse body hash and signature
	bodyHashed, err := decodeBase64String(params["bh"])
	if err != nil {
		return verif, report.fail(VerificationStageParse, permFailError("malformed body hash: "+err.Error()))
	}
	sig, err := decodeBase64String(params["b"])
	if err != nil {
		return verif, report.fail(VerificationStageParse, permFailError("malformed signature: "+err.Error()))
	}

	// Check body hash
	report.setStage(VerificationStageBodyHash)
	hasher := hash.New()
	var w io.Writer = hasher
	if bodyLen >= 0 {
		w = &limitedWriter{W: w, N: bodyLen}
	}
	wc := canonicalizers[bodyCan].CanonicalizeBody(w)
	if _, err := io.Copy(wc, r); err != nil {
		return verif, report.fail(VerificationStageBodyHash, err)
	}
	if err := wc.Close(); err != nil {
		return verif, report.fail(VerificationStageBodyHash, err)
	}
	computedBodyHash := hasher.Sum(nil)
	if report != nil {
		report.BodyDigest = base64.StdEncoding.EncodeToString(computedBodyHash)
	}
	if subtle.ConstantTimeCompare(computedBodyHash, bodyHashed) != 1 {
		return verif, report.fail(VerificationStageBodyHash, failError("body hash did not verify"))
	}

	// Compute data hash
	report.setStage(VerificationStageHeaderHash)
	hasher.Reset()
	picker := newHeaderPicker(h)
	for _, key := range headerKeys {
		kv := picker.Pick(key)
		if kv == "" {
			// The field MAY contain names of header fields that do not exist
			// when signed; nonexistent header fields do not contribute to the
			// signature computation
			continue
		}

		kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return verif, report.fail(VerificationStageHeaderHash, err)
		}
	}
	canSigField := removeSignature(sigField)
	canSigField = canonicalizers[headerCan].CanonicalizeHeader(canSigField)
	canSigField = strings.TrimRight(canSigField, "\r\n")
	if _, err := hasher.Write([]byte(canSigField)); err != nil {
		return verif, report.fail(VerificationStageHeaderHash, err)
	}
	hashed := hasher.Sum(nil)
	if report != nil {
		report.HeaderDigest = base64.StdEncoding.EncodeToString(hashed)
	}

	// Check signature
	report.setStage(VerificationStageCryptoVerify)
	if err := frozenKey.Verify(hash, hashed, sig); err != nil {
		return verif, report.fail(VerificationStageCryptoVerify, failError("signature did not verify: "+err.Error()))
	}

	return verif, nil
}

func parseTagList(s string) []string {
	tags := strings.Split(s, ":")
	for i, t := range tags {
		tags[i] = stripWhitespace(t)
	}
	return tags
}

func parseCanonicalization(s string) (headerCan, bodyCan Canonicalization) {
	headerCan = CanonicalizationSimple
	bodyCan = CanonicalizationSimple

	cans := strings.SplitN(stripWhitespace(s), "/", 2)
	if cans[0] != "" {
		headerCan = Canonicalization(cans[0])
	}
	if len(cans) > 1 {
		bodyCan = Canonicalization(cans[1])
	}
	return
}

func parseTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(stripWhitespace(s), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

func decodeBase64String(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stripWhitespace(s))
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func removeSignature(s string) string {
	return regexp.MustCompile(`(b\s*=)[^;]+`).ReplaceAllString(s, "$1")
}
