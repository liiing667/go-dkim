package dkim

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func testMessageReport(id string, result Status) *MessageReport {
	return &MessageReport{
		Version:    ManifestVersion,
		ID:         id,
		Conclusion: result,
		Signatures: []*SignatureReport{
			{
				Index:     0,
				Domain:    id + ".example",
				Selector:  "selector",
				DNSStatus: DNSOK,
				Result:    result,
			},
		},
	}
}

func TestManifestUpdatePreservesEveryMessage(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-manifest-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")

	first := testMessageReport("first", StatusPass)
	if _, err := UpdateManifestFile(path, first); err != nil {
		t.Fatalf("Updating with first message failed: %v", err)
	}

	second := testMessageReport("second", StatusTempError)
	if _, err := UpdateManifestFile(path, second); err != nil {
		t.Fatalf("Updating with second message failed: %v", err)
	}

	manifest, err := LoadManifestFile(path)
	if err != nil {
		t.Fatalf("Loading manifest failed: %v", err)
	}
	if len(manifest.Messages) != 2 {
		t.Fatalf("Expected both messages to be preserved, got %d", len(manifest.Messages))
	}
	if manifest.Messages[0].ID != "first" || manifest.Messages[0].Conclusion != StatusPass {
		t.Errorf("First message changed: %+v", manifest.Messages[0])
	}
	if manifest.Messages[1].ID != "second" || manifest.Messages[1].Conclusion != StatusTempError {
		t.Errorf("Second message changed: %+v", manifest.Messages[1])
	}
	if got := manifest.Messages[1].Signatures[0].Result; got != StatusTempError {
		t.Errorf("Second message signature result = %q, want %q", got, StatusTempError)
	}
	if got := manifest.Conclusion(); got != StatusTempError {
		t.Errorf("Manifest conclusion = %q, want %q", got, StatusTempError)
	}

	// Re-running the first message must replace only its own record. It must
	// neither append a duplicate nor overwrite the second message.
	firstRetry := testMessageReport("first", StatusFail)
	if _, err := UpdateManifestFile(path, firstRetry); err != nil {
		t.Fatalf("Updating first message again failed: %v", err)
	}
	manifest, err = LoadManifestFile(path)
	if err != nil {
		t.Fatalf("Loading manifest after retry failed: %v", err)
	}
	if len(manifest.Messages) != 2 {
		t.Fatalf("Expected two unique messages after retry, got %d", len(manifest.Messages))
	}
	if manifest.Messages[0].ID != "first" || manifest.Messages[0].Conclusion != StatusFail {
		t.Errorf("Retried message was not updated in place: %+v", manifest.Messages[0])
	}
	if manifest.Messages[1].ID != "second" || manifest.Messages[1].Conclusion != StatusTempError {
		t.Errorf("Retrying a different message overwrote the second message: %+v", manifest.Messages[1])
	}
	if got := manifest.Conclusion(); got != StatusFail {
		t.Errorf("Manifest conclusion after retry = %q, want %q", got, StatusFail)
	}

	temps, err := filepath.Glob(filepath.Join(dir, ".results.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Errorf("Atomic write left temporary files behind: %v", temps)
	}
}

func TestManifestLoadRecoversCompleteLinesAfterTruncatedRecord(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-manifest-recover-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")

	first, err := json.Marshal(testMessageReport("first", StatusPass))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(testMessageReport("second", StatusPermError))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash while appending: the last record is incomplete.
	data := append(append(append([]byte{}, first...), '\n'), second[:len(second)/2]...)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadManifestFile(path)
	if err != nil {
		t.Fatalf("Expected complete records to be recovered, got: %v", err)
	}
	if len(manifest.Messages) != 1 {
		t.Fatalf("Expected one complete recovered message, got %d", len(manifest.Messages))
	}
	if manifest.Messages[0].ID != "first" || manifest.Messages[0].Conclusion != StatusPass {
		t.Errorf("Recovered message mismatch: %+v", manifest.Messages[0])
	}
}

func TestUpdateManifestDoesNotOverwriteUnreadableEvidence(t *testing.T) {
	dir, err := ioutil.TempDir("", "dkim-manifest-corrupt-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "results.json")
	corrupt := []byte("not a manifest\n")
	if err := ioutil.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := UpdateManifestFile(path, testMessageReport("new", StatusPass)); err == nil {
		t.Fatal("Expected updating an unreadable manifest to fail")
	}
	got, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(corrupt) {
		t.Errorf("Unreadable manifest was overwritten: %q", got)
	}
}

func TestManifestEmptyAndArrayFormats(t *testing.T) {
	manifest, err := ReadManifest(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("Empty manifest failed to load: %v", err)
	}
	if manifest.Version != ManifestVersion || len(manifest.Messages) != 0 {
		t.Errorf("Unexpected empty manifest: %+v", manifest)
	}
	if got := manifest.Conclusion(); got != StatusNone {
		t.Errorf("Empty manifest conclusion = %q, want %q", got, StatusNone)
	}

	data, err := json.Marshal([]*MessageReport{testMessageReport("array", StatusPass)})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err = ReadManifest(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Array manifest failed to load: %v", err)
	}
	if len(manifest.Messages) != 1 || manifest.Messages[0].ID != "array" {
		t.Errorf("Unexpected array manifest: %+v", manifest)
	}
}

func TestManifestRecomputesConclusionFromSignatureList(t *testing.T) {
	report := testMessageReport("inconsistent", StatusPass)
	report.Signatures[0].Result = StatusTempError

	if got := report.FinalStatus(); got != StatusTempError {
		t.Errorf("FinalStatus = %q, want %q", got, StatusTempError)
	}
	manifest := NewManifest()
	manifest.Add(report)
	if report.Conclusion != StatusTempError {
		t.Errorf("Message conclusion = %q, want %q", report.Conclusion, StatusTempError)
	}
	if got := manifest.Conclusion(); got != StatusTempError {
		t.Errorf("Manifest conclusion = %q, want %q", got, StatusTempError)
	}
}
