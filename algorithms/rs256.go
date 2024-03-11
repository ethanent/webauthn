package algorithms

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

var rsaVerifyPKCS1v15 func(*rsa.PublicKey, crypto.Hash, []byte, []byte) error = rsa.VerifyPKCS1v15

// RS256 uses RSA keys to verify PKCS#1 v1.5 signatures generated using SHA256.
type RS256 struct{}

func (r *RS256) Value() int {
	return -257
}

func (r *RS256) CheckKeyType(key any) error {
	if _, ok := key.(*rsa.PublicKey); !ok {
		return ErrUnsupportedKeyType
	}
	return nil
}

func (r *RS256) Verify(pub any, message, sig []byte) error {
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrUnsupportedKeyType
	}
	h := sha256.Sum256(message)
	if err := rsaVerifyPKCS1v15(key, crypto.SHA256, h[:], sig); err != nil {
		return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return nil
}
