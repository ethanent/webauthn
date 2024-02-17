package algorithms

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
)

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

func (r *RS256) Verify(pub any, message, sig []byte) (bool, error) {
	key, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, ErrUnsupportedKeyType
	}
	h := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) == nil, nil
}
