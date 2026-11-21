package dkim

import (
	"testing"
)

// Repeated "h=" entries must be bound to concrete header field positions and
// resolved from bottom to top deterministically, as required by RFC 6376
// section 3.7. Re-creating the picker (a retry or a restart re-processing the
// same message) must produce exactly the same sequence of fields.
func TestHeaderPicker_Pick_repeatedKeysStableAcrossRetries(t *testing.T) {
	headers := header{
		"Received: first\r\n",
		"From: legit@example.org\r\n",
		"Received: second\r\n",
		"From: injected@example.org\r\n",
		"Received: third\r\n",
	}
	keys := []string{"Received", "Received", "Received", "From", "From"}

	want := []string{
		"Received: third\r\n",
		"Received: second\r\n",
		"Received: first\r\n",
		"From: injected@example.org\r\n",
		"From: legit@example.org\r\n",
	}

	// Run several independent picker instances to simulate retries/restarts:
	// each attempt must resolve the "h=" list to the exact same header fields.
	for attempt := 0; attempt < 3; attempt++ {
		picker := newHeaderPicker(headers)
		for i, key := range keys {
			got := picker.Pick(key)
			if got != want[i] {
				t.Fatalf("Attempt %v: Pick(%q) #%v = %q, want %q", attempt, key, i, got, want[i])
			}
		}
	}
}

// A header field injected below the signed one must not be selected by a
// later pick for the same name: the picker continues above the previously
// picked field instead of re-scanning the whole header block.
func TestHeaderPicker_Pick_injectedDuplicateDoesNotReplaceSignedField(t *testing.T) {
	headers := header{
		"X-Security: legit\r\n",
		"Subject: hello\r\n",
		"X-Security: injected\r\n",
	}

	picker := newHeaderPicker(headers)
	first := picker.Pick("X-Security")
	if first != "X-Security: injected\r\n" {
		t.Fatalf("first Pick = %q, want the bottom field", first)
	}
	second := picker.Pick("X-Security")
	if second != "X-Security: legit\r\n" {
		t.Fatalf("second Pick = %q, want the field above the first pick", second)
	}
	// No more X-Security fields above the second pick.
	if got := picker.Pick("X-Security"); got != "" {
		t.Fatalf("third Pick = %q, want empty string", got)
	}
}

// Picking a non-existent field must not consume any position, so a later pick
// of an existing field still starts at the bottom of the header block.
func TestHeaderPicker_Pick_missingFieldDoesNotAdvance(t *testing.T) {
	headers := header{
		"From: legit@example.org\r\n",
		"From: injected@example.org\r\n",
	}
	picker := newHeaderPicker(headers)
	if got := picker.Pick("Reply-To"); got != "" {
		t.Fatalf("Pick(missing) = %q, want empty string", got)
	}
	if got := picker.Pick("From"); got != "From: injected@example.org\r\n" {
		t.Fatalf("Pick(From) after missing pick = %q, want the bottom field", got)
	}
}
