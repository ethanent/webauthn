package algorithms

import (
	"crypto/ed25519"
)

// EdDSA uses Ed25519 keys to verify signatures.
type EdDSA struct{}

func (e *EdDSA) Value() int {
	return -8
}

func (e *EdDSA) CheckKeyType(key any) error {
	if _, ok := key.(ed25519.PublicKey); !ok {
		return ErrUnsupportedKeyType
	}
	return nil
}

func (e *EdDSA) Verify(pub any, message, sig []byte) (bool, error) {
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false, ErrUnsupportedKeyType
	}
	return ed25519.Verify(key, message, sig), nil
}
