# go-dkim

[![GoDoc](https://godoc.org/github.com/emersion/go-dkim?status.svg)](https://godoc.org/github.com/emersion/go-dkim)
[![builds.sr.ht status](https://builds.sr.ht/~emersion/go-dkim.svg)](https://builds.sr.ht/~emersion/go-dkim?)
[![codecov](https://codecov.io/gh/emersion/go-dkim/branch/master/graph/badge.svg)](https://codecov.io/gh/emersion/go-dkim)

A Go library to create and verify [DKIM signatures](https://tools.ietf.org/html/rfc6376).

> **Note**: this repository has been migrated to https://github.com/emersion/go-msgauth

## Usage

### Sign

```go
r := strings.NewReader(mailString)

options := &SignOptions{
	Domain: "example.org",
	Selector: "brisbane",
	Signer: privateKey,
}

var b bytes.Buffer
if err := dkim.Sign(&b, r, options); err != nil {
	log.Fatal(err)
}
```

### Verify

```go
r := strings.NewReader(mailString)

verifications, err := dkim.Verify(r)
if err != nil {
	log.Fatal(err)
}

for _, v := range verifications {
	if v.Err == nil {
		log.Println("Valid signature for:", v.Domain)
	} else {
		log.Println("Invalid signature for:", v.Domain, v.Err)
	}
}
```

### DNS key cache and rotation

`Verify` freezes the signature's domain, selector and public-key generation
before it reads the body. The process-wide `KeyCache` is keyed by both domain
and selector, so a key for one selector can never be reused for another. A
rotation is committed only after the new DNS answer has been parsed
completely; a temporary query failure leaves the previous committed generation
intact and fails verification closed.

Temporary DNS failures keep the last complete generation visible for
diagnostics, but it is not used unless a caller explicitly enables stale
fallback. A permanent answer such as a revoked or empty TXT record removes the
old generation so it can never be resurrected.

By default the cache re-checks DNS for every message (zero TTL). Callers that
want to cache a confirmed key for a bounded time can pass their own cache and
report options:

```go
cache := dkim.NewKeyCacheWithTTL(5 * time.Minute)

verifications, err := dkim.VerifyWithOptions(r, &dkim.VerifyOptions{
	KeyCache: cache,
	Reports:  true,
})
```

`VerifyReport` retains the frozen domain, selector, key generation, key
fingerprint, cache source, message hashes and the stage at which verification
failed. A cache snapshot can be persisted and restored with
`KeyCache.Snapshot` and `NewKeyCacheFromSnapshot`.

### FAQ

**Why can't I verify a `mail.Message` directly?** A `mail.Message` header is
already parsed, and whitespace characters (especially continuation lines) are
removed. Thus, the signature computed from the parsed header is not the same as
the one computed from the raw header.

**How can I publish my public key?** You have to add a TXT record to your DNS
zone. See [RFC 6376 appendix C](https://tools.ietf.org/html/rfc6376#appendix-C).

## License

MIT
