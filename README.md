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

`Verify` keeps returning one `Verification` per signature and its historical
error types are unchanged. Existing callers that already have the
`[]*Verification` list can use `dkim.OverallStatus`; new callers can get the
full per-signature report and message conclusion from `VerifyMessage`:

```go
report, err := dkim.VerifyMessage(r)
if err != nil {
	log.Fatal(err)
}

for _, sig := range report.Signatures {
	log.Printf("signature %d: domain=%v dns=%v result=%v",
		sig.Index, sig.Domain, sig.DNSStatus, sig.Result)
}
log.Println("message conclusion:", report.Conclusion)
```

The report is an immutable snapshot of the accepted message: every signature
header, its claimed domain and selector, and the signature order are captured
before verification starts. Each signature keeps its own result. A temporary
failure or a revoked key in any signature can never be folded into an earlier
pass; `Conclusion` is only `pass` when every signature passed, and is `none`
for a message without signatures.

### dkim-verify result manifests

`cmd/dkim-verify` keeps its original stdin/stdout behavior when called without
new options, including its historical exit status of 0 after a message was
parsed even when a signature failed. To keep results for several messages in
one recoverable manifest:

```sh
dkim-verify -manifest results.json < message.eml
dkim-verify -manifest results.json -json < another-message.eml
dkim-verify -manifest results.json -list
```

The manifest file is JSON with one ordered report per message. A different
message is appended instead of replacing the previous one; re-running the same
message replaces only its own record. `-json` prints the current message's
report to stdout while the manifest keeps the full history. Writes are atomic
(temporary file, fsync, rename), and an unreadable existing manifest is
reported instead of being silently overwritten. Complete records can also be
recovered from a line-delimited manifest whose last record was truncated.
`Manifest.Conclusion` returns the worst retained message conclusion, so a
batch consumer cannot report success after any stored message failed. `-list`
prints every retained message and derives its exit status from the same
manifest conclusion.

In manifest, `-strict` or `-json` mode, the exit status and the printed list
come from the same ordered signature list (`MessageReport.FinalStatus`):

| conclusion | exit status |
| --- | --- |
| `none`, `pass` | 0 |
| `fail` | 1 |
| `temperror` | 2 |
| `permerror` | 3 |
| `error` | 4 |

Message read/parse errors still exit with status 1, as before.

### FAQ

**Why can't I verify a `mail.Message` directly?** A `mail.Message` header is
already parsed, and whitespace characters (especially continuation lines) are
removed. Thus, the signature computed from the parsed header is not the same as
the one computed from the raw header.

**How can I publish my public key?** You have to add a TXT record to your DNS
zone. See [RFC 6376 appendix C](https://tools.ietf.org/html/rfc6376#appendix-C).

## License

MIT
