package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-dkim"
)

const unsignedTestMessage = "From: Joe <joe@example.org>\r\n" +
	"Subject: first\r\n" +
	"\r\n" +
	"first body\r\n"

const malformedTestMessage = "DKIM-Signature: v=1; d=bad.example; s=bad; h=from; bh=AAAA; b=AAAA\r\n" +
	"From: Joe <joe@example.org>\r\n" +
	"Subject: second\r\n" +
	"\r\n" +
	"second body\r\n"

func TestRunLegacyCommandSemanticsStayUnchanged(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, strings.NewReader(malformedTestMessage), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Legacy invocation exit code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "Invalid signature for bad.example") {
		t.Errorf("Expected the historical invalid-signature log, got %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("Legacy invocation unexpectedly wrote stdout: %q", stdout.String())
	}
}

func TestRunManifestPreservesPreviousMessages(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-verify-manifest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-manifest", path}, strings.NewReader(unsignedTestMessage), &stdout, &stderr); code != 0 {
		t.Fatalf("Unsigned message exit code = %d, want 0: %s", code, stderr.String())
	}

	secondMessage := strings.Replace(unsignedTestMessage, "first body", "second body", 1)
	if code := run([]string{"-manifest", path}, strings.NewReader(secondMessage), &stdout, &stderr); code != 0 {
		t.Fatalf("Second unsigned message exit code = %d, want 0: %s", code, stderr.String())
	}

	manifest, err := dkim.LoadManifestFile(path)
	if err != nil {
		t.Fatalf("Loading manifest failed: %v", err)
	}
	if len(manifest.Messages) != 2 {
		t.Fatalf("Expected two preserved messages, got %d", len(manifest.Messages))
	}
	if manifest.Messages[0].ID == manifest.Messages[1].ID {
		t.Error("Different messages received the same manifest identity")
	}
	for i, message := range manifest.Messages {
		if message.Conclusion != dkim.StatusNone || len(message.Signatures) != 0 {
			t.Errorf("Message %d should be an unsigned none result, got %+v", i, message)
		}
	}
}

func TestRunManifestExitStatusComesFromReport(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-verify-exit-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-manifest", path}, strings.NewReader(malformedTestMessage), &stdout, &stderr)
	if code != exitCodeFor(dkim.StatusPermError) {
		t.Fatalf("Exit code = %d, want %d", code, exitCodeFor(dkim.StatusPermError))
	}
	if !strings.Contains(stderr.String(), "result=permerror") {
		t.Errorf("Expected per-signature list in output, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "message ") || !strings.Contains(stderr.String(), ": permerror") {
		t.Errorf("Expected message conclusion in output, got %q", stderr.String())
	}

	manifest, err := dkim.LoadManifestFile(path)
	if err != nil {
		t.Fatalf("Loading manifest failed: %v", err)
	}
	if len(manifest.Messages) != 1 {
		t.Fatalf("Expected one message, got %d", len(manifest.Messages))
	}
	report := manifest.Messages[0]
	if report.Conclusion != dkim.StatusPermError || len(report.Signatures) != 1 {
		t.Fatalf("Unexpected manifest report: %+v", report)
	}
	if report.Signatures[0].Domain != "bad.example" || report.Signatures[0].DNSStatus != dkim.DNSNotQueried {
		t.Errorf("Unexpected signature report: %+v", report.Signatures[0])
	}
}

func TestRunJSONOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-json"}, strings.NewReader(unsignedTestMessage), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("JSON invocation exit code = %d: %s", code, stderr.String())
	}

	var report dkim.MessageReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Invalid report JSON: %v\n%s", err, stdout.String())
	}
	if report.Conclusion != dkim.StatusNone || len(report.Signatures) != 0 {
		t.Errorf("Unexpected report: %+v", report)
	}
}

func TestRunStrictExitStatuses(t *testing.T) {
	tests := []struct {
		status dkim.Status
		code   int
	}{
		{dkim.StatusNone, 0},
		{dkim.StatusPass, 0},
		{dkim.StatusFail, 1},
		{dkim.StatusTempError, 2},
		{dkim.StatusPermError, 3},
		{dkim.StatusError, 4},
	}
	for _, test := range tests {
		if got := exitCodeFor(test.status); got != test.code {
			t.Errorf("exitCodeFor(%q) = %d, want %d", test.status, got, test.code)
		}
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-strict"}, strings.NewReader(malformedTestMessage), &stdout, &stderr); code != 3 {
		t.Errorf("Strict malformed signature exit code = %d, want 3", code)
	}
}

func TestRunListUsesManifestConclusion(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-verify-list-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")

	manifest := dkim.NewManifest()
	manifest.Add(&dkim.MessageReport{
		ID: "passing",
		Signatures: []*dkim.SignatureReport{
			{Index: 0, Domain: "pass.example", Result: dkim.StatusPass, DNSStatus: dkim.DNSOK},
		},
	})
	manifest.Add(&dkim.MessageReport{
		ID: "temporary",
		Signatures: []*dkim.SignatureReport{
			{Index: 0, Domain: "temp.example", Result: dkim.StatusTempError, DNSStatus: dkim.DNSTempError},
		},
	})
	if err := dkim.SaveManifestFile(path, manifest); err != nil {
		t.Fatalf("Saving manifest failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-manifest", path, "-list"}, strings.NewReader("ignored"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("List exit code = %d, want 2: %s", code, stderr.String())
	}
	for _, want := range []string{"message passing: pass", "message temporary: temperror"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("List output %q does not contain %q", stderr.String(), want)
		}
	}
}
