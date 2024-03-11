package algorithms

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestRS256Verify(t *testing.T) {
	tests := []struct {
		pub     any
		message []byte
		sig     []byte

		verifyExpectHashed string
		verifyReturns      error

		expect error
	}{
		{
			pub:           &rsa.PublicKey{},
			message:       []byte("hello"),
			sig:           []byte("sig"),
			verifyReturns: nil,
			expect:        nil,
		},
		{
			pub:           &rsa.PublicKey{},
			message:       []byte("hello2"),
			sig:           []byte("sig2"),
			verifyReturns: errors.New("bad sig"),
			expect:        ErrVerificationFailed,
		},
		{
			pub:           ed25519.PublicKey{},
			verifyReturns: nil,
			expect:        ErrUnsupportedKeyType,
		},
	}

	r := &RS256{}

	for _, test := range tests {
		rsaVerifyPKCS1v15 = func(*rsa.PublicKey, crypto.Hash, []byte, []byte) error {
			return test.verifyReturns
		}
		err := r.Verify(test.pub, test.message, test.sig)
		if test.expect == nil {
			if err != nil {
				t.Errorf("got error '%v', expected nil", err)
			}
		} else {
			if !errors.Is(err, test.expect) {
				t.Errorf("got error '%v', expected '%v' to be in chain", err, test.expect)
			}
		}
	}
}
