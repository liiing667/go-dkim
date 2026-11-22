package dkim

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
)

// KeySource describes where a verification key came from.
type KeySource string

// CacheSource is an alias for KeySource.
type CacheSource = KeySource

const (
	// KeySourceNone means that no key source is available.
	KeySourceNone KeySource = ""
	// KeySourceDNS means that the key was fetched from DNS during this
	// verification.
	KeySourceDNS KeySource = "dns"
	// KeySourceCache means that the key was served from an already committed
	// cache generation.
	KeySourceCache KeySource = "cache"
)

// String constants for consumers that keep the cache origin in a string
// report field.
const (
	CacheSourceNone  = "none"
	CacheSourceDNS   = "dns"
	CacheSourceCache = "cache"
)

// PublicKeyFingerprint returns a stable identifier of a DKIM public key: the
// hex-encoded SHA-256 digest of its DER-encoded SubjectPublicKeyInfo. It is
// used to prove that a signature, a cached key and a verification report all
// refer to the exact same key material.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := marshalPublicKeyDER(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func marshalPublicKeyDER(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err == nil {
		return der, nil
	}

	// Older Go versions don't know about golang.org/x/crypto/ed25519 public
	// keys. Their SubjectPublicKeyInfo encoding is fixed, so provide it
	// explicitly in that case.
	if edPub, ok := pub.(ed25519.PublicKey); ok && len(edPub) == ed25519.PublicKeySize {
		return marshalEd25519SPKI(edPub), nil
	}

	return nil, fmt.Errorf("dkim: failed to marshal public key: %v", err)
}

func marshalEd25519SPKI(pub ed25519.PublicKey) []byte {
	// SEQUENCE {
	//   SEQUENCE { OBJECT IDENTIFIER 1.3.101.112 }
	//   BIT STRING (32 bytes)
	// }
	der := []byte{
		0x30, 0x2a,
		0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
		0x03, 0x21, 0x00,
	}
	return append(der, pub...)
}

// Key is an immutable snapshot of a DKIM public key generation.
//
// A Key captures the domain, selector, generation number and public key
// material that were in effect when verification started. Later rotations or
// cache updates cannot change an existing Key.
type Key struct {
	// Domain is the SDID ("d=") the key belongs to.
	Domain string
	// Selector is the selector ("s=") the key was published under.
	Selector string
	// Generation is the cache generation that produced this snapshot.
	Generation uint64
	// Fingerprint is the SHA-256 fingerprint of the public key.
	Fingerprint string

	// KeyAlgo is the DKIM key algorithm ("rsa" or "ed25519").
	KeyAlgo string
	// HashAlgos is the optional list of allowed hash algorithms.
	HashAlgos []string
	// Notes is the optional key note.
	Notes string
	// Services is the optional list of allowed services.
	Services []string
	// Flags is the optional list of key flags.
	Flags []string
	// Source says whether this snapshot was fetched from DNS or served from
	// the cache.
	Source KeySource

	verifier verifier
}

// KeyGeneration is an alias for Key, kept for callers that prefer the
// generation-oriented name.
type KeyGeneration = Key

// Public returns the public key carried by the snapshot.
func (k *Key) Public() crypto.PublicKey {
	if k == nil || k.verifier == nil {
		return nil
	}
	return k.verifier.Public()
}

// Verify checks a signature with the public key of the snapshot.
func (k *Key) Verify(hash crypto.Hash, hashed, sig []byte) error {
	if k == nil || k.verifier == nil {
		return failError("no public key")
	}
	return k.verifier.Verify(hash, hashed, sig)
}

func (k *Key) cloneForRequest(domain, selector string, source KeySource) *Key {
	if k == nil {
		return nil
	}
	return &Key{
		Domain:      domain,
		Selector:    selector,
		Generation:  k.Generation,
		Fingerprint: k.Fingerprint,
		KeyAlgo:     k.KeyAlgo,
		HashAlgos:   cloneStrings(k.HashAlgos),
		Notes:       k.Notes,
		Services:    cloneStrings(k.Services),
		Flags:       cloneStrings(k.Flags),
		Source:      source,
		verifier:    k.verifier,
	}
}

func sameKeyMaterial(a, b *Key) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Fingerprint == b.Fingerprint &&
		a.KeyAlgo == b.KeyAlgo &&
		stringSlicesEqual(a.HashAlgos, b.HashAlgos) &&
		stringSlicesEqual(a.Services, b.Services) &&
		stringSlicesEqual(a.Flags, b.Flags)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

// Query fetches and parses a DKIM public key without consulting a cache. The
// returned Key has generation zero and is not committed anywhere.
//
// Most callers should use Verify, VerifyWithOptions or a KeyCache instead:
// those functions freeze one key generation for the whole verification.
func Query(domain, selector string, methods ...string) (*Key, error) {
	return QueryMethods(domain, selector, methods)
}

// QueryMethods is like Query but accepts the "q=" query methods from a
// DKIM-Signature header field. If methods is empty, dns/txt is used.
func QueryMethods(domain, selector string, methods []string) (*Key, error) {
	res, err := queryKeyResult(domain, selector, methods)
	if err != nil {
		return nil, err
	}
	return newKeyFromResult(domain, selector, res)
}

func queryKeyResult(domain, selector string, methods []string) (*queryResult, error) {
	if len(methods) == 0 {
		methods = []string{string(QueryMethodDNSTXT)}
	}

	for _, method := range methods {
		method = stripWhitespace(method)
		query, ok := queryMethods[QueryMethod(method)]
		if !ok {
			continue
		}
		res, err := query(domain, selector)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, permFailError("no key for signature: empty query result")
		}
		return res, nil
	}

	return nil, permFailError("unsupported public key query method")
}

func newKeyFromResult(domain, selector string, res *queryResult) (*Key, error) {
	if res == nil || res.Verifier == nil {
		return nil, permFailError("no key for signature")
	}

	k := &Key{
		Domain:    domain,
		Selector:  selector,
		KeyAlgo:   res.KeyAlgo,
		HashAlgos: cloneStrings(res.HashAlgos),
		Notes:     res.Notes,
		Services:  cloneStrings(res.Services),
		Flags:     cloneStrings(res.Flags),
		Source:    KeySourceDNS,
		verifier:  cloneVerifier(res.Verifier),
	}

	fingerprint, err := PublicKeyFingerprint(k.Public())
	if err != nil {
		return nil, permFailError("key syntax error: " + err.Error())
	}
	k.Fingerprint = fingerprint

	return k, nil
}

func cloneVerifier(v verifier) verifier {
	if v == nil {
		return nil
	}
	switch pub := v.(type) {
	case rsaVerifier:
		if pub.PublicKey == nil {
			return pub
		}
		return rsaVerifier{cloneRSAPublicKey(pub.PublicKey)}
	case *rsaVerifier:
		if pub == nil {
			return nil
		}
		if pub.PublicKey == nil {
			return pub
		}
		return &rsaVerifier{cloneRSAPublicKey(pub.PublicKey)}
	case ed25519Verifier:
		return ed25519Verifier{append(ed25519.PublicKey(nil), pub.PublicKey...)}
	case *ed25519Verifier:
		if pub == nil {
			return nil
		}
		return &ed25519Verifier{append(ed25519.PublicKey(nil), pub.PublicKey...)}
	}
	return v
}

func cloneRSAPublicKey(pub *rsa.PublicKey) *rsa.PublicKey {
	cloned := *pub
	if pub.N != nil {
		cloned.N = new(big.Int).Set(pub.N)
	}
	return &cloned
}

type keyCacheKey struct {
	domain   string
	selector string
}

func makeKeyCacheKey(domain, selector string) keyCacheKey {
	return keyCacheKey{
		domain:   strings.ToLower(domain),
		selector: strings.ToLower(selector),
	}
}

type keyCacheEntry struct {
	key      *Key
	storedAt time.Time
	querySeq uint64
}

// KeyCache stores immutable public-key generations. Entries are keyed by both
// domain and selector, so a key published for one selector can never be used
// for another selector of the same domain.
//
// By default a cache hold time of zero makes every verification re-check DNS.
// The cache still provides stable generation numbers, atomic commit semantics
// and an immutable snapshot for the duration of a verification. Callers may
// opt in to a non-zero TTL with NewKeyCacheWithTTL or SetTTL.
//
// KeyCache is safe for concurrent use.
type KeyCache struct {
	mu sync.Mutex

	entries map[keyCacheKey]*keyCacheEntry

	// nextGeneration is the last generation number assigned by this cache.
	nextGeneration uint64
	// nextQuery is the last query sequence number assigned by this cache.
	// Sequence numbers prevent a slow, older DNS answer from replacing a
	// newer answer that has already been committed.
	nextQuery uint64
	// epoch changes on a full-state restore. Queries that started before the
	// restore may still resolve a frozen key, but they must not overwrite the
	// restored cache.
	epoch uint64

	ttl        time.Duration
	now        func() time.Time
	allowStale bool
}

// NewKeyCache creates an empty key cache. An optional TTL may be supplied as
// the first argument. A zero TTL means that every verification asks DNS for
// the authoritative current key.
func NewKeyCache(ttl ...time.Duration) *KeyCache {
	c := &KeyCache{
		entries: make(map[keyCacheKey]*keyCacheEntry),
		now:     keyCacheNow,
	}
	if len(ttl) > 0 {
		c.SetTTL(ttl[0])
	}
	return c
}

// NewKeyCacheWithTTL creates an empty key cache that may serve a committed
// generation for ttl without querying DNS again. A non-positive ttl is treated
// as zero (always re-check DNS).
func NewKeyCacheWithTTL(ttl time.Duration) *KeyCache {
	return NewKeyCache(ttl)
}

// SetTTL changes how long a committed generation may be served from the cache.
// A non-positive duration disables cache hits.
func (c *KeyCache) SetTTL(ttl time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if ttl < 0 {
		ttl = 0
	}
	c.ttl = ttl
	c.mu.Unlock()
}

// TTL returns the configured cache hold time.
func (c *KeyCache) TTL() time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ttl
}

// SetAllowStale controls what happens when a DNS refresh fails. When false
// (the default), the failure is returned and the last complete generation is
// left untouched but is not used for the new message. When true, a complete
// cached generation is served instead. Revoked keys must never be recovered
// this way, so the default is fail-closed.
func (c *KeyCache) SetAllowStale(allow bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.allowStale = allow
	c.mu.Unlock()
}

// SetClock overrides the clock used for TTL checks. It is primarily useful in
// tests. Passing nil restores the default DKIM clock.
func (c *KeyCache) SetClock(clock func() time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if clock == nil {
		c.now = keyCacheNow
	} else {
		c.now = clock
	}
	c.mu.Unlock()
}

func (c *KeyCache) ensureLocked() {
	if c.entries == nil {
		c.entries = make(map[keyCacheKey]*keyCacheEntry)
	}
	if c.now == nil {
		c.now = keyCacheNow
	}
}

func (c *KeyCache) clockLocked() time.Time {
	return c.now()
}

func keyCacheNow() time.Time {
	if now != nil {
		return now()
	}
	return time.Now()
}

// Len returns the number of committed selector generations.
func (c *KeyCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// LastGeneration returns the most recent generation number assigned by this
// cache. It is zero when no generation has been committed yet.
func (c *KeyCache) LastGeneration() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextGeneration
}

// Get returns the committed key for an exact domain and selector. It returns
// false when the entry is missing or when a configured TTL has expired.
func (c *KeyCache) Get(domain, selector string) (*Key, bool) {
	if c == nil {
		return nil, false
	}
	id := makeKeyCacheKey(domain, selector)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()

	entry := c.entries[id]
	if entry == nil || entry.key == nil {
		return nil, false
	}
	if c.ttl > 0 {
		age := c.clockLocked().Sub(entry.storedAt)
		if age < 0 || age >= c.ttl {
			return nil, false
		}
	}
	return entry.key.cloneForRequest(domain, selector, KeySourceCache), true
}

// Peek returns the last complete committed key for an exact domain and
// selector, regardless of TTL. It is intended for diagnostics and evidence;
// verification should use Resolve.
func (c *KeyCache) Peek(domain, selector string) (*Key, bool) {
	if c == nil {
		return nil, false
	}
	id := makeKeyCacheKey(domain, selector)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()

	entry := c.entries[id]
	if entry == nil || entry.key == nil {
		return nil, false
	}
	return entry.key.cloneForRequest(domain, selector, KeySourceCache), true
}

// Invalidate removes one selector from the cache. The next Resolve queries
// DNS afresh and commits a new generation. Queries that started before the
// invalidation are not allowed to repopulate the entry.
func (c *KeyCache) Invalidate(domain, selector string) {
	if c == nil {
		return
	}
	id := makeKeyCacheKey(domain, selector)
	c.mu.Lock()
	delete(c.entries, id)
	c.epoch++
	c.mu.Unlock()
}

// Clear removes every committed generation. It is useful when the caller
// knows that the DNS configuration changed wholesale.
func (c *KeyCache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[keyCacheKey]*keyCacheEntry)
	c.epoch++
	c.mu.Unlock()
}

// Reset clears every entry and restarts generation numbering from zero. It is
// useful for tests and for an explicit full restart.
func (c *KeyCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[keyCacheKey]*keyCacheEntry)
	c.nextGeneration = 0
	c.nextQuery = 0
	c.epoch++
	c.mu.Unlock()
}

// Resolve freezes one key generation for a verification. It uses the default
// dns/txt query method when methods is empty.
func (c *KeyCache) Resolve(domain, selector string, methods ...string) (*Key, error) {
	return c.ResolveMethods(domain, selector, methods)
}

// Lookup is an alias for Resolve.
func (c *KeyCache) Lookup(domain, selector string, methods ...string) (*Key, error) {
	return c.Resolve(domain, selector, methods...)
}

// Query is an alias for Resolve on a KeyCache.
func (c *KeyCache) Query(domain, selector string, methods ...string) (*Key, error) {
	return c.Resolve(domain, selector, methods...)
}

// LookupMethods is an alias for ResolveMethods.
func (c *KeyCache) LookupMethods(domain, selector string, methods []string) (*Key, error) {
	return c.ResolveMethods(domain, selector, methods)
}

// ResolveMethods freezes one key generation for a verification. The returned
// Key is an immutable snapshot: concurrent rotations and later cache updates
// cannot change the selector, generation, fingerprint or key material it
// carries.
//
// A failed DNS query never partially updates the cache. The previous complete
// entry remains available via Peek/Get, while the current verification fails
// closed unless stale fallback was explicitly enabled.
func (c *KeyCache) ResolveMethods(domain, selector string, methods []string) (*Key, error) {
	if c == nil {
		return nil, permFailError("no key cache")
	}

	id := makeKeyCacheKey(domain, selector)

	c.mu.Lock()
	c.ensureLocked()
	var startKey *Key
	startUsable := false
	var startStoredAt time.Time
	if entry := c.entries[id]; entry != nil && entry.key != nil {
		startKey = entry.key.cloneForRequest(domain, selector, KeySourceCache)
		startStoredAt = entry.storedAt
		startUsable = c.ttl == 0
	}
	if c.ttl > 0 && startKey != nil {
		age := c.clockLocked().Sub(startStoredAt)
		if age >= 0 && age < c.ttl {
			c.mu.Unlock()
			return startKey, nil
		}
	}
	c.nextQuery++
	querySeq := c.nextQuery
	queryEpoch := c.epoch
	c.mu.Unlock()

	res, err := queryKeyResult(domain, selector, methods)
	if err != nil {
		c.mu.Lock()
		if c.epoch != queryEpoch {
			c.mu.Unlock()
			return nil, err
		}
		entry := c.entries[id]
		if IsPermFail(err) {
			if entry != nil && entry.querySeq > querySeq {
				c.mu.Unlock()
				return nil, err
			}
			// A permanent answer means the selector no longer has a usable
			// key (for example it was revoked or the TXT record is empty).
			// Remove the old generation so it can never be resurrected by a
			// later stale fallback.
			delete(c.entries, id)
			c.epoch++
			c.mu.Unlock()
			return nil, err
		}
		if c.allowStale && IsTempFail(err) && entry != nil && entry.key != nil {
			if startUsable {
				c.mu.Unlock()
				return startKey, nil
			}
			key := entry.key.cloneForRequest(domain, selector, KeySourceCache)
			c.mu.Unlock()
			return key, nil
		}
		c.mu.Unlock()
		return nil, err
	}

	key, err := newKeyFromResult(domain, selector, res)
	if err != nil {
		c.mu.Lock()
		if c.epoch == queryEpoch {
			entry := c.entries[id]
			if entry == nil || entry.querySeq <= querySeq {
				delete(c.entries, id)
				c.epoch++
			}
		}
		c.mu.Unlock()
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()

	if c.epoch != queryEpoch {
		if startUsable {
			return startKey, nil
		}
		if entry := c.entries[id]; entry != nil && entry.key != nil {
			return entry.key.cloneForRequest(domain, selector, KeySourceCache), nil
		}
		c.nextGeneration++
		key.Generation = c.nextGeneration
		key.Source = KeySourceDNS
		return key.cloneForRequest(domain, selector, KeySourceDNS), nil
	}

	entry := c.entries[id]
	if entry != nil && entry.querySeq > querySeq {
		if startUsable {
			return startKey, nil
		}
		// A newer DNS answer has already been committed. Never let this
		// slower, older answer roll the selector back to an older key.
		if entry.key != nil {
			return entry.key.cloneForRequest(domain, selector, KeySourceCache), nil
		}
		return nil, tempFailError("key cache changed while querying")
	}

	if entry != nil && entry.key != nil && sameKeyMaterial(entry.key, key) {
		entry.storedAt = c.clockLocked()
		entry.querySeq = querySeq
		return entry.key.cloneForRequest(domain, selector, KeySourceCache), nil
	}

	c.nextGeneration++
	key.Generation = c.nextGeneration
	key.Source = KeySourceDNS
	c.entries[id] = &keyCacheEntry{
		key:      key,
		storedAt: c.clockLocked(),
		querySeq: querySeq,
	}
	return key.cloneForRequest(domain, selector, KeySourceDNS), nil
}

var defaultKeyCache = NewKeyCache()

// DefaultKeyCache returns the cache used by Verify and VerifyWithOptions when
// no cache is supplied explicitly.
func DefaultKeyCache() *KeyCache {
	return defaultKeyCache
}

// KeyCacheEntrySnapshot is the serializable form of one committed selector
// generation.
type KeyCacheEntrySnapshot struct {
	Domain      string    `json:"domain"`
	Selector    string    `json:"selector"`
	Generation  uint64    `json:"generation"`
	Fingerprint string    `json:"fingerprint"`
	KeyAlgo     string    `json:"key_algo"`
	// PublicKey is the raw Ed25519 public key or the DER-encoded RSA public
	// key, matching the encoding used by the DKIM "p=" tag.
	PublicKey   []byte    `json:"public_key"`
	HashAlgos   []string  `json:"hash_algos,omitempty"`
	Notes       string    `json:"notes,omitempty"`
	Services    []string  `json:"services,omitempty"`
	Flags       []string  `json:"flags,omitempty"`
	StoredAt    time.Time `json:"stored_at"`
	QuerySeq    uint64    `json:"query_seq"`
}

// KeyCacheSnapshot is a complete, self-contained view of a key cache. It can
// be persisted and restored after a restart. Restore is atomic: either every
// entry is accepted or the cache is left unchanged.
type KeyCacheSnapshot struct {
	// NextGeneration is the last generation number assigned by the cache.
	NextGeneration uint64                 `json:"next_generation"`
	// NextQuery is the last query sequence number assigned by the cache.
	NextQuery      uint64                 `json:"next_query"`
	Entries        []KeyCacheEntrySnapshot `json:"entries"`
}

// Snapshot returns a complete copy of the committed cache state.
func (c *KeyCache) Snapshot() (KeyCacheSnapshot, error) {
	var snap KeyCacheSnapshot
	if c == nil {
		return snap, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureLocked()

	snap.NextGeneration = c.nextGeneration
	snap.NextQuery = c.nextQuery
	snap.Entries = make([]KeyCacheEntrySnapshot, 0, len(c.entries))

	for _, entry := range c.entries {
		if entry == nil || entry.key == nil {
			continue
		}
		publicKey, err := publicKeyForSnapshot(entry.key)
		if err != nil {
			return KeyCacheSnapshot{}, fmt.Errorf("dkim: failed to snapshot key %q/%q: %v",
				entry.key.Domain, entry.key.Selector, err)
		}
		snap.Entries = append(snap.Entries, KeyCacheEntrySnapshot{
			Domain:      entry.key.Domain,
			Selector:    entry.key.Selector,
			Generation:  entry.key.Generation,
			Fingerprint: entry.key.Fingerprint,
			KeyAlgo:     entry.key.KeyAlgo,
			PublicKey:   publicKey,
			HashAlgos:   cloneStrings(entry.key.HashAlgos),
			Notes:       entry.key.Notes,
			Services:    cloneStrings(entry.key.Services),
			Flags:       cloneStrings(entry.key.Flags),
			StoredAt:    entry.storedAt,
			QuerySeq:    entry.querySeq,
		})
	}

	sort.Slice(snap.Entries, func(i, j int) bool {
		if snap.Entries[i].Domain != snap.Entries[j].Domain {
			return snap.Entries[i].Domain < snap.Entries[j].Domain
		}
		return snap.Entries[i].Selector < snap.Entries[j].Selector
	})

	return snap, nil
}

func publicKeyForSnapshot(key *Key) ([]byte, error) {
	if key.KeyAlgo == "ed25519" {
		pub, ok := key.Public().(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key")
		}
		return append([]byte(nil), pub...), nil
	}
	return marshalPublicKeyDER(key.Public())
}

// Restore atomically replaces the cache with a previously taken snapshot.
func (c *KeyCache) Restore(snap KeyCacheSnapshot) error {
	if c == nil {
		return fmt.Errorf("dkim: no key cache")
	}

	entries := make(map[keyCacheKey]*keyCacheEntry, len(snap.Entries))
	nextGeneration := snap.NextGeneration
	nextQuery := snap.NextQuery

	for _, item := range snap.Entries {
		key, err := keyFromSnapshot(item)
		if err != nil {
			return err
		}
		id := makeKeyCacheKey(item.Domain, item.Selector)
		if _, exists := entries[id]; exists {
			return fmt.Errorf("dkim: duplicate key cache entry for %q/%q", item.Domain, item.Selector)
		}
		entries[id] = &keyCacheEntry{
			key:      key,
			storedAt: item.StoredAt,
			querySeq: item.QuerySeq,
		}
		if item.Generation > nextGeneration {
			nextGeneration = item.Generation
		}
		if item.QuerySeq > nextQuery {
			nextQuery = item.QuerySeq
		}
	}

	c.mu.Lock()
	if c.nextGeneration > nextGeneration {
		nextGeneration = c.nextGeneration
	}
	if c.nextQuery > nextQuery {
		nextQuery = c.nextQuery
	}
	c.entries = entries
	c.nextGeneration = nextGeneration
	c.nextQuery = nextQuery
	c.epoch++
	if c.now == nil {
		c.now = keyCacheNow
	}
	c.mu.Unlock()
	return nil
}

// NewKeyCacheFromSnapshot creates a cache from a snapshot. It is useful after
// a restart when the caller has persisted a previous KeyCacheSnapshot.
func NewKeyCacheFromSnapshot(snap KeyCacheSnapshot) (*KeyCache, error) {
	c := NewKeyCache()
	if err := c.Restore(snap); err != nil {
		return nil, err
	}
	return c, nil
}

func keyFromSnapshot(item KeyCacheEntrySnapshot) (*Key, error) {
	if len(item.PublicKey) == 0 {
		return nil, fmt.Errorf("dkim: key cache snapshot for %q/%q has no public key",
			item.Domain, item.Selector)
	}

	parts := []string{
		"v=DKIM1",
		"k=" + item.KeyAlgo,
		"p=" + base64.StdEncoding.EncodeToString(item.PublicKey),
	}
	if len(item.HashAlgos) > 0 {
		parts = append(parts, "h="+strings.Join(item.HashAlgos, ":"))
	}
	if len(item.Services) > 0 {
		parts = append(parts, "s="+strings.Join(item.Services, ":"))
	}
	if len(item.Flags) > 0 {
		parts = append(parts, "t="+strings.Join(item.Flags, ":"))
	}

	res, err := parsePublicKey(strings.Join(parts, "; "))
	if err != nil {
		return nil, fmt.Errorf("dkim: invalid key cache snapshot for %q/%q: %v",
			item.Domain, item.Selector, err)
	}
	key, err := newKeyFromResult(item.Domain, item.Selector, res)
	if err != nil {
		return nil, fmt.Errorf("dkim: invalid key cache snapshot for %q/%q: %v",
			item.Domain, item.Selector, err)
	}
	if item.Fingerprint != "" && item.Fingerprint != key.Fingerprint {
		return nil, fmt.Errorf("dkim: key cache snapshot fingerprint mismatch for %q/%q",
			item.Domain, item.Selector)
	}

	key.KeyAlgo = item.KeyAlgo
	key.Notes = item.Notes
	key.Generation = item.Generation
	key.Source = KeySourceCache
	return key, nil
}

