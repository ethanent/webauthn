package algorithms

import (
	"crypto/ed25519"
)

var ed25519Verify func(ed25519.PublicKey, []byte, []byte) bool = ed25519.Verify

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

func (e *EdDSA) Verify(pub any, message, sig []byte) error {
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ErrUnsupportedKeyType
	}
	if !ed25519Verify(key, message, sig) {
		return ErrVerificationFailed
	}
	return nil
}
