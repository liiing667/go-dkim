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

### Key rotation and reports

When the signing key is rotated, each signing session must keep using one key
generation (selector + private key) for its whole lifetime — including
retries after a transient failure. Use a `KeyRing`, take an immutable
`SigningKey` snapshot per message and attach a `SignReport`:

```go
ring := dkim.NewKeyRing()
if _, err := ring.Rotate("brisbane", privateKey); err != nil {
	log.Fatal(err)
}

key, err := ring.Snapshot() // pinned generation; rotations don't affect it
if err != nil {
	log.Fatal(err)
}

report := &dkim.SignReport{}
err = dkim.Sign(w, r, &dkim.SignOptions{
	Domain:     "example.org",
	Key:        key,
	MaxRetries: 2,
	Report:     report,
})
```

The report retains the selector, the public-key fingerprint, the body and
header message digests and the pipeline stage reached; on failure it points
at the exact failing stage. Verification reports are available through
`VerifyWithOptions` with `VerifyOptions{Reports: true}`.

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

### FAQ

**Why can't I verify a `mail.Message` directly?** A `mail.Message` header is
already parsed, and whitespace characters (especially continuation lines) are
removed. Thus, the signature computed from the parsed header is not the same as
the one computed from the raw header.

**How can I publish my public key?** You have to add a TXT record to your DNS
zone. See [RFC 6376 appendix C](https://tools.ietf.org/html/rfc6376#appendix-C).

## License

MIT
