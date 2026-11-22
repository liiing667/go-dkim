package dkim

import (
	"bytes"
	"errors"
	"testing"
)

func TestLocalSignCancelDoesNotPublishPartialSignature(t *testing.T) {
	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	}

	s, err := NewSigner(options)
	if err != nil {
		t.Fatal("Expected no error while creating signer, got:", err)
	}

	if _, err := s.Write([]byte(mailHeaderString)); err != nil {
		t.Fatal("Expected no error while writing header, got:", err)
	}
	if _, err := s.Write([]byte(mailBodyString[:8])); err != nil {
		t.Fatal("Expected no error while writing partial body, got:", err)
	}

	if err := s.Cancel(); err != ErrSignerCanceled {
		t.Errorf("Expected Cancel to return %v, got %v", ErrSignerCanceled, err)
	}
	if err := s.Close(); err != ErrSignerCanceled {
		t.Errorf("Expected Close after Cancel to return %v, got %v", ErrSignerCanceled, err)
	}

	defer func() {
		if recover() == nil {
			t.Error("Expected Signature to panic after a canceled signer")
		}
	}()
	s.Signature()
}

func TestLocalSignCloseWithErrorDiscardsSignature(t *testing.T) {
	options := &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	}

	s, err := NewSigner(options)
	if err != nil {
		t.Fatal("Expected no error while creating signer, got:", err)
	}

	cancelErr := errors.New("test cancellation")
	if err := s.CloseWithError(cancelErr); err != cancelErr {
		t.Errorf("Expected CloseWithError to return %v, got %v", cancelErr, err)
	}
}

type localSignFailingReader struct{}

func (localSignFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("test read failure")
}

func TestLocalSignReaderFailureDoesNotWritePartialMessage(t *testing.T) {
	var b bytes.Buffer
	err := Sign(&b, localSignFailingReader{}, &SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   testPrivateKey,
	})
	if err == nil {
		t.Fatal("Expected an error when the input reader fails")
	}
	if b.Len() != 0 {
		t.Errorf("Expected no signed message to be written, got %q", b.String())
	}
}
