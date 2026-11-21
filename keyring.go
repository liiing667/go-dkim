package dkim

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

// KeyGeneration is an immutable signing key generation. Every time the
// signing key is rotated, a new KeyGeneration is produced with an incremented
// generation number, a new selector and a new private key.
//
// A KeyGeneration is safe to use concurrently: it only carries immutable
// material, so the same generation can be reused for retries without ever
// observing a rotated key mid-signature.
type KeyGeneration struct {
	// Generation is the monotonically increasing key generation number. The
	// first generation is 0.
	Generation uint64
	// Selector is the DNS selector ("s=") published together with the public
	// key of this generation.
	Selector string
	// Signer is the private key used to sign messages of this generation.
	Signer crypto.Signer
}

// Fingerprint returns a stable identifier of the generation's public key: the
// hex-encoded SHA-256 digest of the DER-encoded SubjectPublicKeyInfo. It can
// be used to prove that a signature and a report refer to the exact same key
// material.
func (g *KeyGeneration) Fingerprint() (string, error) {
	return PublicKeyFingerprint(g.Signer.Public())
}

// PublicKeyFingerprint returns the hex-encoded SHA-256 digest of the
// DER-encoded SubjectPublicKeyInfo of pub.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("dkim: failed to marshal public key: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// KeyRing holds the history of DKIM signing key generations. Rotating the key
// appends a new generation while previous generations are kept so that
// messages already signed with them can still be explained in reports.
//
// KeyRing is safe for concurrent use: rotations and snapshots are serialized
// through a mutex and every returned SigningKey is an immutable snapshot.
type KeyRing struct {
	generations []*KeyGeneration
	mu          chan struct{}
}

// NewKeyRing creates a key ring containing generations.
func NewKeyRing(generations ...*KeyGeneration) *KeyRing {
	kr := &KeyRing{mu: make(chan struct{}, 1)}
	kr.mu <- struct{}{}
	for _, g := range generations {
		kr.add(g)
	}
	return kr
}

func (kr *KeyRing) lock()   { <-kr.mu }
func (kr *KeyRing) unlock() { kr.mu <- struct{}{} }

// Add appends a generation to the key ring. The generation number is assigned
// automatically: the first generation is 0, each subsequent rotation gets the
// previous number plus one. An empty selector or signer is rejected.
func (kr *KeyRing) Add(selector string, signer crypto.Signer) (*KeyGeneration, error) {
	if selector == "" {
		return nil, fmt.Errorf("dkim: no selector specified")
	}
	if signer == nil {
		return nil, fmt.Errorf("dkim: no signer specified")
	}

	kr.lock()
	defer kr.unlock()
	return kr.add(&KeyGeneration{Selector: selector, Signer: signer}), nil
}

// add must be called with the lock held.
func (kr *KeyRing) add(g *KeyGeneration) *KeyGeneration {
	g.Generation = uint64(len(kr.generations))
	kr.generations = append(kr.generations, g)
	return g
}

// Rotate appends a new generation with the given selector and private key and
// returns it. It is a convenience wrapper around Add.
func (kr *KeyRing) Rotate(selector string, signer crypto.Signer) (*KeyGeneration, error) {
	return kr.Add(selector, signer)
}

// Current returns the most recently added key generation, or nil if the ring
// is empty.
func (kr *KeyRing) Current() *KeyGeneration {
	kr.lock()
	defer kr.unlock()
	if len(kr.generations) == 0 {
		return nil
	}
	return kr.generations[len(kr.generations)-1]
}

// Generation returns the generation with the given number, or nil if no such
// generation exists.
func (kr *KeyRing) Generation(n uint64) *KeyGeneration {
	kr.lock()
	defer kr.unlock()
	if n >= uint64(len(kr.generations)) {
		return nil
	}
	return kr.generations[n]
}

// Len returns the number of generations the ring holds.
func (kr *KeyRing) Len() int {
	kr.lock()
	defer kr.unlock()
	return len(kr.generations)
}

// SigningKey is the immutable key snapshot a single signing session (including
// all of its retries) is pinned to. It captures the selector and the private
// key at session creation time, so a concurrent rotation cannot make the
// signature value come from a different private key than the one advertised by
// the selector in the DKIM-Signature header field.
type SigningKey struct {
	generation uint64
	selector   string
	signer     crypto.Signer
}

// Snapshot pins the current key generation. Every subsequent signing attempt
// of the returned SigningKey keeps using the same selector and private key,
// even if the ring is rotated afterwards. It returns an error if the ring is
// empty.
func (kr *KeyRing) Snapshot() (*SigningKey, error) {
	g := kr.Current()
	if g == nil {
		return nil, fmt.Errorf("dkim: key ring is empty")
	}
	return g.signingKey(), nil
}

// SnapshotGeneration pins the key generation with the given number. It
// returns an error if no such generation exists.
func (kr *KeyRing) SnapshotGeneration(n uint64) (*SigningKey, error) {
	g := kr.Generation(n)
	if g == nil {
		return nil, fmt.Errorf("dkim: unknown key generation %v", n)
	}
	return g.signingKey(), nil
}

func (g *KeyGeneration) signingKey() *SigningKey {
	return &SigningKey{
		generation: g.Generation,
		selector:   g.Selector,
		signer:     g.Signer,
	}
}

// NewSigningKey creates a standalone signing key snapshot. It is useful for
// callers that don't need a full KeyRing but still want a reportable,
// fingerprintable key snapshot.
func NewSigningKey(selector string, signer crypto.Signer) (*SigningKey, error) {
	if selector == "" {
		return nil, fmt.Errorf("dkim: no selector specified")
	}
	if signer == nil {
		return nil, fmt.Errorf("dkim: no signer specified")
	}
	return &SigningKey{selector: selector, signer: signer}, nil
}

// Generation returns the key generation number the snapshot belongs to. It is
// zero for standalone keys created with NewSigningKey.
func (k *SigningKey) Generation() uint64 { return k.generation }

// Selector returns the selector pinned to this snapshot.
func (k *SigningKey) Selector() string { return k.selector }

// Signer returns the private key pinned to this snapshot.
func (k *SigningKey) Signer() crypto.Signer { return k.signer }

// Fingerprint returns the fingerprint of the snapshot's public key.
func (k *SigningKey) Fingerprint() (string, error) {
	return PublicKeyFingerprint(k.signer.Public())
}

// supportedKeyAlgo returns the DKIM key algorithm tag ("rsa" or "ed25519")
// for the snapshot's public key.
func (k *SigningKey) supportedKeyAlgo() (string, error) {
	switch k.signer.Public().(type) {
	case *rsa.PublicKey:
		return "rsa", nil
	case ed25519.PublicKey:
		return "ed25519", nil
	default:
		return "", fmt.Errorf("dkim: unsupported key algorithm %T", k.signer.Public())
	}
}
