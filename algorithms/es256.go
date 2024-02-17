package algorithms

import (
	"crypto/ecdsa"
	"crypto/sha256"
)

// ES256 uses ECDSA keys to verify ASN.1 signatures of SHA256 hashes.
type ES256 struct{}

func (e *ES256) Value() int {
	return -7
}

func (e *ES256) CheckKeyType(key any) error {
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		return ErrUnsupportedKeyType
	}
	return nil
}

func (e *ES256) Verify(pub any, message, sig []byte) (bool, error) {
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, ErrUnsupportedKeyType
	}
	h := sha256.Sum256(message)
	return ecdsa.VerifyASN1(key, h[:], sig), nil
}
