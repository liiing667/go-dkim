package dkim

import "encoding/base64"

// SigningStage identifies a stage of the DKIM signing pipeline.
type SigningStage string

const (
	// SigningStageOptions is the option validation stage.
	SigningStageOptions SigningStage = "options"
	// SigningStageReadHeader is the message header reading stage.
	SigningStageReadHeader SigningStage = "read-header"
	// SigningStageBodyHash is the canonicalized body hashing stage ("bh=").
	SigningStageBodyHash SigningStage = "body-hash"
	// SigningStageHeaderHash is the canonicalized header hashing stage.
	SigningStageHeaderHash SigningStage = "header-hash"
	// SigningStageCryptoSign is the private-key signature stage ("b=").
	SigningStageCryptoSign SigningStage = "crypto-sign"
	// SigningStageFormat is the signature header formatting stage.
	SigningStageFormat SigningStage = "format"
)

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

// ErrorStage returns the pipeline stage recorded on a report's error. The
// signing and verification errors keep their historical concrete types
// (permFailError, tempFailError, failError) so that IsPermFail, IsTempFail
// and friends keep working; the stage is carried by the report instead of
// wrapping the error.
func ErrorStage(err error) string {
	if se, ok := err.(*stageError); ok {
		return se.stage
	}
	return ""
}

// stageError is only stored inside a report. It deliberately does not
// implement the perm/temp/fail failure-type interfaces: errors returned to
// callers are always the original, unwrapped errors.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

func newStageError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &stageError{stage: stage, err: err}
}

// SignReport describes a signing run, including any retry. All fields are
// populated while the message flows through the pipeline, so even a failed
// run leaves a report explaining which key generation was used and at which
// stage the failure happened.
type SignReport struct {
	// Domain is the SDID ("d=") the message is signed for.
	Domain string
	// Selector is the selector ("s=") of the pinned key generation.
	Selector string
	// KeyGeneration is the key generation number the run is pinned to. It
	// stays identical across retries.
	KeyGeneration uint64
	// KeyFingerprint is the SHA-256 fingerprint (hex) of the pinned public
	// key.
	KeyFingerprint string

	// BodyDigest is the base64-encoded canonicalized body hash ("bh=").
	BodyDigest string
	// HeaderDigest is the base64-encoded hash of the signed header data,
	// i.e. the data that is handed to the private key.
	HeaderDigest string

	// Stage is the pipeline stage the run reached. On success it is the last
	// stage, on failure it is the failing stage.
	Stage SigningStage
	// Attempts is the number of signing attempts performed (1 on the first
	// try, more when a retry happened).
	Attempts int

	// Err is the first error encountered, wrapped with its stage. It is nil
	// on success. The error returned by Close/Verify is always the original
	// failure; this field additionally remembers the stage at which it
	// happened.
	Err error
}

func (r *SignReport) setStage(stage SigningStage) {
	if r != nil {
		r.Stage = stage
	}
}

// fail records the stage and the error on the report and returns the
// original error unchanged, so failure-type assertions keep working.
func (r *SignReport) fail(stage SigningStage, err error) error {
	if r != nil {
		r.Stage = stage
		r.Err = &stageError{stage: string(stage), err: err}
	}
	return err
}

// VerifyReport describes the verification of one DKIM-Signature header field.
type VerifyReport struct {
	// Domain is the SDID claimed by the signature ("d=").
	Domain string
	// Selector is the selector claimed by the signature ("s=").
	Selector string
	// KeyFingerprint is the SHA-256 fingerprint (hex) of the public key
	// returned by the DNS query.
	KeyFingerprint string

	// BodyDigest is the base64-encoded body hash claimed by the signature
	// ("bh=").
	BodyDigest string
	// HeaderDigest is the base64-encoded hash locally computed over the
	// signed header data.
	HeaderDigest string

	// Stage is the pipeline stage the verification reached. On failure it is
	// the failing stage.
	Stage VerificationStage
	// Err is the verification error with its stage recorded. It is nil when
	// the signature is valid.
	Err error
}

func (r *VerifyReport) setStage(stage VerificationStage) {
	if r != nil {
		r.Stage = stage
	}
}

// fail records the stage and the error on the report and returns the
// original error unchanged, so failure-type assertions keep working.
func (r *VerifyReport) fail(stage VerificationStage, err error) error {
	if r != nil {
		r.Stage = stage
		r.Err = &stageError{stage: string(stage), err: err}
	}
	return err
}

func encodeDigest(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
