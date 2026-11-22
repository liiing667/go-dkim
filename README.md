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

### Milter message transactions

`cmd/dkim-milter` treats one SMTP message as one transaction. At the first
header field it starts a new generation and captures the `Message-ID`; when the
header block ends it freezes the header and body digest inputs. A signer,
verification results and pending `Authentication-Results` edits belong only to
that generation. A new message, `Abort`, `Reset` or a body-stage failure
cancels the previous signer and verifier stream before the next message is
accepted.

The resulting `Authentication-Results` value keeps the existing DKIM result
tokens (`pass`, `fail`, `permerror`, `temperror` or `none`) and appends
transaction evidence as a comment:

```
mx.example.org; dkim=pass header.d=example.org
 (dkim-milter generation=2 message-id=<id@example.org>
  header-sha256=... body-sha256=... body-bytes=... stage=commit)
```

This makes the committed signature and report refer to the same message. A
retry of an already committed `Message-ID` with the same header/body snapshot
replays the original signature and report; different content under that
identity is rejected rather than re-signed. Unsigned mail is still reported as
`dkim=none`, recipients do not create separate transactions, and
`Authentication-Results` fields written by other authserv-ids are left in
place.

### FAQ

**Why can't I verify a `mail.Message` directly?** A `mail.Message` header is
already parsed, and whitespace characters (especially continuation lines) are
removed. Thus, the signature computed from the parsed header is not the same as
the one computed from the raw header.

**How can I publish my public key?** You have to add a TXT record to your DNS
zone. See [RFC 6376 appendix C](https://tools.ietf.org/html/rfc6376#appendix-C).

## License

MIT
