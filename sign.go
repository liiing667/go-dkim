package dkim

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

var randReader io.Reader = rand.Reader

// SignOptions is used to configure Sign. Domain is mandatory, and either a
// SigningKey (Key) or both Selector and Signer must be provided.
type SignOptions struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream. Hence, the SDID value is used to form the query for the public
	// key. The SDID MUST correspond to a valid DNS name under which the DKIM key
	// record is published.
	//
	// This can't be empty.
	Domain string
	// The selector subdividing the namespace for the domain.
	//
	// This can't be empty.
	Selector string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	//
	// This is optional.
	Identifier string

	// The key used to sign the message.
	//
	// Supported Signer.Public() values are *rsa.PublicKey and
	// ed25519.PublicKey.
	Signer crypto.Signer
	// Key optionally pins the whole signing session (selector, private key and
	// key generation) to an immutable snapshot taken before the message is
	// processed. When set, Selector and Signer are ignored: every signing
	// attempt, including retries after a transient failure, keeps using the
	// exact same key generation, so a concurrent key rotation can never make
	// the signature value come from another private key than the selector
	// advertised in the DKIM-Signature header field.
	Key *SigningKey

	// Report, if non-nil, is populated while the message flows through the
	// signing pipeline. It retains the selector, key fingerprint, message
	// digests and the stage reached, and on failure it points at the exact
	// failing stage.
	Report *SignReport

	// MaxRetries is the number of additional attempts allowed when the private
	// key operation fails transiently. Zero means a single attempt (no retry),
	// which preserves the historical behavior. Retries reuse the pinned Key
	// snapshot and the already computed message hashes.
	MaxRetries int
	// The hash algorithm used to sign the message. If zero, a default hash will
	// be chosen.
	//
	// The only supported hash algorithm is crypto.SHA256.
	Hash crypto.Hash

	// Header and body canonicalization algorithms.
	//
	// If empty, CanonicalizationSimple is used.
	HeaderCanonicalization Canonicalization
	BodyCanonicalization   Canonicalization

	// A list of header fields to include in the signature. If nil, all headers
	// will be included. If not nil, "From" MUST be in the list.
	//
	// See RFC 6376 section 5.4.1 for recommended header fields.
	HeaderKeys []string

	// The expiration time. A zero value means no expiration.
	Expiration time.Time

	// A list of query methods used to retrieve the public key.
	//
	// If nil, it is implicitly defined as QueryMethodDNSTXT.
	QueryMethods []QueryMethod
}

// Signer generates a DKIM signature.
//
// The whole message header and body must be written to the Signer. Close should
// always be called (either after the whole message has been written, or after
// an error occured and the signer won't be used anymore). Close may return an
// error in case signing fails.
//
// After a successful Close, Signature can be called to retrieve the
// DKIM-Signature header field that the caller should prepend to the message.
type Signer struct {
	pw          *io.PipeWriter
	done        <-chan error
	sig         string // only valid after done received nil
	report      *SignReport
	maxAttempts int
}

// NewSigner creates a new signer. It returns an error if SignOptions is
// invalid.
func NewSigner(options *SignOptions) (*Signer, error) {
	if options == nil {
		return nil, fmt.Errorf("dkim: no options specified")
	}
	if options.Domain == "" {
		return nil, fmt.Errorf("dkim: no domain specified")
	}

	// Pin the key generation before anything else. A SigningKey snapshot is
	// immutable, so retries cannot accidentally pick up a rotated private key
	// while the selector still names the old generation.
	key := options.Key
	if key == nil {
		var err error
		key, err = NewSigningKey(options.Selector, options.Signer)
		if err != nil {
			return nil, err
		}
	}

	report := options.Report
	if report == nil {
		report = &SignReport{}
	}
	report.Domain = options.Domain
	report.Selector = key.Selector()
	report.KeyGeneration = key.Generation()
	fingerprint, err := key.Fingerprint()
	if err != nil {
		report.Err = newStageError(string(SigningStageOptions), err)
		return nil, err
	}
	report.KeyFingerprint = fingerprint
	report.Stage = SigningStageOptions
	if options.MaxRetries < 0 {
		options.MaxRetries = 0
	}

	headerCan := options.HeaderCanonicalization
	if headerCan == "" {
		headerCan = CanonicalizationSimple
	}
	if _, ok := canonicalizers[headerCan]; !ok {
		return nil, fmt.Errorf("dkim: unknown header canonicalization %q", headerCan)
	}

	bodyCan := options.BodyCanonicalization
	if bodyCan == "" {
		bodyCan = CanonicalizationSimple
	}
	if _, ok := canonicalizers[bodyCan]; !ok {
		return nil, fmt.Errorf("dkim: unknown body canonicalization %q", bodyCan)
	}

	keyAlgo, err := key.supportedKeyAlgo()
	if err != nil {
		return nil, err
	}

	hash := options.Hash
	var hashAlgo string
	switch options.Hash {
	case 0: // sha256 is the default
		hash = crypto.SHA256
		fallthrough
	case crypto.SHA256:
		hashAlgo = "sha256"
	case crypto.SHA1:
		return nil, fmt.Errorf("dkim: hash algorithm too weak: sha1")
	default:
		return nil, fmt.Errorf("dkim: unsupported hash algorithm")
	}

	if options.HeaderKeys != nil {
		ok := false
		for _, k := range options.HeaderKeys {
			if strings.EqualFold(k, "From") {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("dkim: the From header field must be signed")
		}
	}

	done := make(chan error, 1)
	pr, pw := io.Pipe()

	s := &Signer{
		pw:          pw,
		done:        done,
		report:      report,
		maxAttempts: options.MaxRetries + 1,
	}

	closeReadWithError := func(err error) {
		pr.CloseWithError(err)
		done <- err
	}

	go func() {
		report.setStage(SigningStageReadHeader)
		// Read header
		br := bufio.NewReader(pr)
		h, err := readHeader(br)
		if err != nil {
			closeReadWithError(report.fail(SigningStageReadHeader, err))
			return
		}

		// Hash body
		report.setStage(SigningStageBodyHash)
		hasher := hash.New()
		can := canonicalizers[bodyCan].CanonicalizeBody(hasher)
		if _, err := io.Copy(can, br); err != nil {
			closeReadWithError(report.fail(SigningStageBodyHash, err))
			return
		}
		if err := can.Close(); err != nil {
			closeReadWithError(report.fail(SigningStageBodyHash, err))
			return
		}
		bodyHashed := hasher.Sum(nil)
		report.BodyDigest = encodeDigest(bodyHashed)

		params := map[string]string{
			"v":  "1",
			"a":  keyAlgo + "-" + hashAlgo,
			"bh": report.BodyDigest,
			"c":  string(headerCan) + "/" + string(bodyCan),
			"d":  options.Domain,
			//"l": "", // TODO
			"s": key.Selector(),
			"t": formatTime(now()),
			//"z": "", // TODO
		}

		var headerKeys []string
		if options.HeaderKeys != nil {
			headerKeys = options.HeaderKeys
		} else {
			for _, kv := range h {
				k, _ := parseHeaderField(kv)
				headerKeys = append(headerKeys, k)
			}
		}
		params["h"] = formatTagList(headerKeys)

		if options.Identifier != "" {
			params["i"] = options.Identifier
		}

		if options.QueryMethods != nil {
			methods := make([]string, len(options.QueryMethods))
			for i, method := range options.QueryMethods {
				methods[i] = string(method)
			}
			params["q"] = formatTagList(methods)
		}

		if !options.Expiration.IsZero() {
			params["x"] = formatTime(options.Expiration)
		}

		// Hash and sign headers
		report.setStage(SigningStageHeaderHash)
		hasher.Reset()
		picker := newHeaderPicker(h)
		for _, k := range headerKeys {
			kv := picker.Pick(k)
			if kv == "" {
				// The Signer MAY include more instances of a header field name
				// in "h=" than there are actual corresponding header fields so
				// that the signature will not verify if additional header
				// fields of that name are added.
				continue
			}

			kv = canonicalizers[headerCan].CanonicalizeHeader(kv)
			if _, err := io.WriteString(hasher, kv); err != nil {
				closeReadWithError(report.fail(SigningStageHeaderHash, err))
				return
			}
		}

		params["b"] = ""
		sigField := formatSignature(params)
		sigField = canonicalizers[headerCan].CanonicalizeHeader(sigField)
		sigField = strings.TrimRight(sigField, crlf)
		if _, err := io.WriteString(hasher, sigField); err != nil {
			closeReadWithError(report.fail(SigningStageHeaderHash, err))
			return
		}
		hashed := hasher.Sum(nil)
		report.HeaderDigest = encodeDigest(hashed)

		// Sign with the pinned key generation. The message snapshot (hashes)
		// is computed once: retries only re-run the private-key operation, so
		// a transient crypto failure can never mix selector and key material
		// from different generations.
		report.setStage(SigningStageCryptoSign)
		var sig []byte
		for attempt := 1; attempt <= s.maxAttempts; attempt++ {
			report.Attempts = attempt
			sig, err = key.Signer().Sign(randReader, hashed, hash)
			if err == nil {
				break
			}
			if attempt == s.maxAttempts {
				closeReadWithError(report.fail(SigningStageCryptoSign, err))
				return
			}
		}

		report.setStage(SigningStageFormat)
		params["b"] = base64.StdEncoding.EncodeToString(sig)

		s.sig = formatSignature(params)
		closeReadWithError(nil)
		close(done)
	}()

	return s, nil
}

// Write implements io.WriteCloser.
func (s *Signer) Write(b []byte) (n int, err error) {
	return s.pw.Write(b)
}

// Close implements io.WriteCloser. The error return by Close must be checked.
func (s *Signer) Close() error {
	if err := s.pw.Close(); err != nil {
		return err
	}
	return <-s.done
}

// Signature returns the whole DKIM-Signature header field. It can only be
// called after a successful Signer.Close call.
//
// The returned value contains both the header field name, its value and the
// final CRLF.
func (s *Signer) Signature() string {
	if s.sig == "" {
		panic("dkim: Signer.Signature must only be called after a succesful Signer.Close")
	}
	return s.sig
}

// Report returns the report of the signing run. It can be called after Close.
// The returned pointer is the SignOptions.Report value when one was provided,
// otherwise it's an internally allocated report.
func (s *Signer) Report() *SignReport {
	return s.report
}

// Sign signs a message. It reads it from r and writes the signed version to w.
func Sign(w io.Writer, r io.Reader, options *SignOptions) error {
	s, err := NewSigner(options)
	if err != nil {
		return err
	}
	defer s.Close()

	// We need to keep the message in a buffer so we can write the new DKIM
	// header field before the rest of the message
	var b bytes.Buffer
	mw := io.MultiWriter(&b, s)

	if _, err := io.Copy(mw, r); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}

	if _, err := io.WriteString(w, s.Signature()); err != nil {
		return err
	}
	_, err = io.Copy(w, &b)
	return err
}

func formatSignature(params map[string]string) string {
	sig := headerFieldName + ": " + formatHeaderParams(params)
	return foldHeaderField(sig)
}

func formatTagList(l []string) string {
	return strings.Join(l, ":")
}

func formatTime(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
