package dkim

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
)

func marshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
