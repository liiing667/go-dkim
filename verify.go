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
	_, ok := err.(permFailError)
	return ok
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dkim: " + string(err)
}

// IsTempFail returns true if the error returned by Verify is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

type failError string

func (err failError) Error() string {
	return "dkim: " + string(err)
}

// isFail returns true if the error returned by Verify is a signature error.
func isFail(err error) bool {
	_, ok := err.(failError)
	return ok
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
	// HeaderInstances lists the concrete header field occurrences consumed by
	// this signature, in the same order as HeaderKeys. Entries in HeaderKeys
	// which do not exist in the message do not consume an instance and are
	// therefore absent from this list.
	HeaderInstances []HeaderInstance
	// The number of bytes in the body which are signed. If the whole body is
	// signed, BodyLength is < 0.
	BodyLength int64

	// The time that this signature was created. If unknown, it's set to zero.
	Time time.Time
	// The expiration time. If the signature doesn't expire, it's set to zero.
	Expiration time.Time

	// Err is nil if the signature is valid.
	Err error
}

type signature struct {
	i int
	v string
}

// messageGeneration is the immutable message snapshot shared by all signatures
// checked during one Verify call. Header selection, canonicalization and body
// hashing operate on this snapshot instead of re-reading mutable input.
type messageGeneration struct {
	header header
	body   []byte
}

// Verify checks if a message's signatures are valid. It returns one
// verification per signature.
//
// The header and body are read once into an immutable message generation. Each
// signature then gets its own reader over the same body bytes and its own
// binding to concrete header field occurrences.
func Verify(r io.Reader) ([]*Verification, error) {
	// TODO: be able to specify options such as the max number of signatures to
	// check

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

	if len(signatures) == 0 {
		return []*Verification{}, nil
	}

	// Snapshot the whole body once. Every signature is verified against this
	// same generation, so a failed verification cannot consume bytes needed by
	// a retry or by a later signature.
	body, err := ioutil.ReadAll(bufr)
	if err != nil {
		return nil, err
	}
	gen := &messageGeneration{
		header: append(header(nil), h...),
		body:   body,
	}

	verifications := make([]*Verification, len(signatures))
	var firstUnclassifiedErr error
	for i, sig := range signatures {
		v, err := verifyGeneration(gen, gen.header[sig.i], sig.v)
		if err != nil && !IsTempFail(err) && !IsPermFail(err) && !isFail(err) {
			if firstUnclassifiedErr == nil {
				firstUnclassifiedErr = err
			}
		}

		v.Err = err
		verifications[i] = v
	}
	return verifications, firstUnclassifiedErr
}

func verify(h header, r io.Reader, sigField, sigValue string) (*Verification, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return &Verification{}, err
	}
	gen := &messageGeneration{
		header: append(header(nil), h...),
		body:   body,
	}
	return verifyGeneration(gen, sigField, sigValue)
}

func verifyGeneration(gen *messageGeneration, sigField, sigValue string) (*Verification, error) {
	verif := new(Verification)

	params, err := parseHeaderParams(sigValue)
	if err != nil {
		return verif, permFailError("malformed signature tags: " + err.Error())
	}

	var headerKeys []string
	if h, ok := params["h"]; ok {
		headerKeys = parseTagList(h)
	}
	verif.HeaderKeys = append([]string(nil), headerKeys...)
	if headerKeys != nil {
		// Bind h= to concrete physical header instances before any later
		// verification stage can fail. A retry starts from this same report,
		// never from a picker cursor left behind by a failed attempt.
		verif.HeaderInstances = bindHeaderInstances(gen.header, headerKeys)
	}

	if params["v"] != "1" {
		return verif, permFailError("incompatible signature version")
	}

	verif.Domain = stripWhitespace(params["d"])

	for _, tag := range requiredTags {
		if _, ok := params[tag]; !ok {
			return verif, permFailError("signature missing required tag")
		}
	}

	if i, ok := params["i"]; ok {
		verif.Identifier = stripWhitespace(i)
		if !strings.HasSuffix(verif.Identifier, "@"+verif.Domain) && !strings.HasSuffix(verif.Identifier, "."+verif.Domain) {
			return verif, permFailError("domain mismatch")
		}
	} else {
		verif.Identifier = "@" + verif.Domain
	}

	ok := false
	for _, k := range headerKeys {
		if strings.ToLower(k) == "from" {
			ok = true
			break
		}
	}
	if !ok {
		return verif, permFailError("From field not signed")
	}

	if timeStr, ok := params["t"]; ok {
		t, err := parseTime(timeStr)
		if err != nil {
			return verif, permFailError("malformed time: " + err.Error())
		}
		verif.Time = t
	}
	if expiresStr, ok := params["x"]; ok {
		t, err := parseTime(expiresStr)
		if err != nil {
			return verif, permFailError("malformed expiration time: " + err.Error())
		}
		verif.Expiration = t
		if now().After(t) {
			return verif, permFailError("signature has expired")
		}
	}

	// Query public key
	// TODO: compute hash in parallel
	methods := []string{string(QueryMethodDNSTXT)}
	if methodsStr, ok := params["q"]; ok {
		methods = parseTagList(methodsStr)
	}
	var res *queryResult
	for _, method := range methods {
		if query, ok := queryMethods[QueryMethod(method)]; ok {
			res, err = query(verif.Domain, stripWhitespace(params["s"]))
			break
		}
	}
	if err != nil {
		return verif, err
	} else if res == nil {
		return verif, permFailError("unsupported public key query method")
	}

	// Parse algos
	algos := strings.SplitN(stripWhitespace(params["a"]), "-", 2)
	if len(algos) != 2 {
		return verif, permFailError("malformed algorithm name")
	}
	keyAlgo := algos[0]
	hashAlgo := algos[1]

	// Check hash algo
	if res.HashAlgos != nil {
		ok := false
		for _, algo := range res.HashAlgos {
			if algo == hashAlgo {
				ok = true
				break
			}
		}
		if !ok {
			return verif, permFailError("inappropriate hash algorithm")
		}
	}
	var hash crypto.Hash
	switch hashAlgo {
	case "sha1":
		// RFC 8301 section 3.1: rsa-sha1 MUST NOT be used for signing or
		// verifying.
		return verif, permFailError(fmt.Sprintf("hash algorithm too weak: %v", hashAlgo))
	case "sha256":
		hash = crypto.SHA256
	default:
		return verif, permFailError("unsupported hash algorithm")
	}

	// Check key algo
	if res.KeyAlgo != keyAlgo {
		return verif, permFailError("inappropriate key algorithm")
	}

	if res.Services != nil {
		ok := false
		for _, s := range res.Services {
			if s == "email" {
				ok = true
				break
			}
		}
		if !ok {
			return verif, permFailError("inappropriate service")
		}
	}

	headerCan, bodyCan := parseCanonicalization(params["c"])
	if _, ok := canonicalizers[headerCan]; !ok {
		return verif, permFailError("unsupported header canonicalization algorithm")
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return verif, permFailError("unsupported body canonicalization algorithm")
	}

	var bodyLen int64 = -1
	if lenStr, ok := params["l"]; ok {
		l, err := strconv.ParseInt(stripWhitespace(lenStr), 10, 64)
		if err != nil {
			return verif, permFailError("malformed body length: " + err.Error())
		} else if l < 0 {
			return verif, permFailError("malformed body length: negative value")
		}
		bodyLen = l
	}
	verif.BodyLength = bodyLen

	// Parse body hash and signature
	bodyHashed, err := decodeBase64String(params["bh"])
	if err != nil {
		return verif, permFailError("malformed body hash: " + err.Error())
	}
	sig, err := decodeBase64String(params["b"])
	if err != nil {
		return verif, permFailError("malformed signature: " + err.Error())
	}

	// Check body hash
	hasher := hash.New()
	var w io.Writer = hasher
	if bodyLen >= 0 {
		w = &limitedWriter{W: w, N: bodyLen}
	}
	wc := canonicalizers[bodyCan].CanonicalizeBody(w)
	if _, err := io.Copy(wc, bytes.NewReader(gen.body)); err != nil {
		return verif, err
	}
	if err := wc.Close(); err != nil {
		return verif, err
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), bodyHashed) != 1 {
		return verif, failError("body hash did not verify")
	}

	// Compute data hash
	hasher.Reset()
	for _, instance := range verif.HeaderInstances {
		kv := canonicalizers[headerCan].CanonicalizeHeader(instance.Raw)
		if _, err := hasher.Write([]byte(kv)); err != nil {
			return verif, err
		}
	}
	canSigField := removeSignature(sigField)
	canSigField = canonicalizers[headerCan].CanonicalizeHeader(canSigField)
	canSigField = strings.TrimRight(canSigField, "\r\n")
	if _, err := hasher.Write([]byte(canSigField)); err != nil {
		return verif, err
	}
	hashed := hasher.Sum(nil)

	// Check signature
	if err := res.Verifier.Verify(hash, hashed, sig); err != nil {
		return verif, failError("signature did not verify: " + err.Error())
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
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return s
	}

	// Walk the tag list instead of using a regular expression: the base64
	// values of other tags (in particular bh=) may themselves contain the
	// byte sequence "b=" and must not be mistaken for the signature tag.
	i := colon + 1
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == ';') {
			i++
		}
		if i >= len(s) {
			break
		}

		nameStart := i
		for i < len(s) && s[i] != '=' && s[i] != ';' {
			i++
		}
		name := strings.TrimSpace(s[nameStart:i])
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && s[i] != ';' {
				i++
			}
			continue
		}

		i++ // skip '='
		valueStart := i
		for i < len(s) && s[i] != ';' {
			i++
		}
		if strings.EqualFold(name, "b") {
			// Keep the b= tag itself but remove its value, including any
			// folding whitespace inside it. Everything after the semicolon is
			// preserved byte-for-byte.
			return s[:valueStart] + s[i:]
		}
	}

	return s
}
