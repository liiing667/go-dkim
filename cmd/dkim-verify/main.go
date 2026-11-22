package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/emersion/go-dkim"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes dkim-verify and returns its process exit status. Keeping the
// entry point small makes the exit-status/list contract testable.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dkim-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var manifestPath string
	var outputJSON bool
	var strict bool
	var listManifest bool

	fs.StringVar(&manifestPath, "manifest", "", "recoverable result manifest file")
	fs.StringVar(&manifestPath, "o", "", "alias for -manifest")
	fs.StringVar(&manifestPath, "output", "", "alias for -manifest")
	fs.BoolVar(&outputJSON, "json", false, "write the verification report or manifest as JSON")
	fs.BoolVar(&strict, "strict", false, "derive the exit status from the message conclusion")
	fs.BoolVar(&strict, "check", false, "alias for -strict")
	fs.BoolVar(&listManifest, "list", false, "list every message in the manifest")

	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 1
	}

	logger := log.New(stderr, "", log.LstdFlags)

	if listManifest {
		if manifestPath == "" {
			logger.Print("dkim-verify: -list requires -manifest")
			return 1
		}
		manifest, err := dkim.LoadManifestFile(manifestPath)
		if err != nil {
			logger.Print(err)
			return 1
		}
		if outputJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(manifest); err != nil {
				logger.Print(err)
				return 1
			}
		} else {
			for _, message := range manifest.Messages {
				printReport(stderr, message)
			}
		}
		return exitCodeFor(manifest.Conclusion())
	}

	// Preserve the historical command contract for existing callers: without
	// any of the new options, print one line per signature and only fail on a
	// message read/parse error.
	if manifestPath == "" && !outputJSON && !strict {
		verifications, err := dkim.Verify(stdin)
		if err != nil {
			logger.Print(err)
			return 1
		}
		for _, v := range verifications {
			if v.Err == nil {
				logger.Printf("Valid signature for %v", v.Domain)
			} else {
				logger.Printf("Invalid signature for %v: %v", v.Domain, v.Err)
			}
		}
		return 0
	}

	report, err := dkim.VerifyMessage(stdin)
	if err != nil {
		logger.Print(err)
		return 1
	}

	if manifestPath != "" {
		if _, err := dkim.UpdateManifestFile(manifestPath, report); err != nil {
			logger.Print(err)
			return 1
		}
	}

	if outputJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			logger.Print(err)
			return 1
		}
	} else {
		printReport(stderr, report)
	}

	return exitCodeFor(report.FinalStatus())
}

func printReport(w io.Writer, report *dkim.MessageReport) {
	if report == nil {
		return
	}
	conclusion := report.FinalStatus()
	if len(report.Signatures) == 0 {
		fmt.Fprintf(w, "message %s: %s (no DKIM signatures)\n", shortID(report.ID), conclusion)
		return
	}
	for _, sig := range report.Signatures {
		fmt.Fprintf(w, "signature %d: domain=%s selector=%s dns=%s result=%s",
			sig.Index, sig.Domain, sig.Selector, sig.DNSStatus, sig.Result)
		if sig.Error != "" {
			fmt.Fprintf(w, " error=%q", sig.Error)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "message %s: %s\n", shortID(report.ID), conclusion)
}

func shortID(id string) string {
	const n = 16
	if len(id) > n {
		return id[:n]
	}
	return id
}

// exitCodeFor is the single exit-status mapping used by the manifest and
// report consumers. It is derived from MessageReport.FinalStatus, which
// recomputes the conclusion from the same ordered signature list that is
// printed, so the list and the exit status cannot disagree.
func exitCodeFor(status dkim.Status) int {
	switch status {
	case dkim.StatusNone, dkim.StatusPass:
		return 0
	case dkim.StatusFail:
		return 1
	case dkim.StatusTempError:
		return 2
	case dkim.StatusPermError:
		return 3
	case dkim.StatusError:
		return 4
	default:
		return 4
	}
}
