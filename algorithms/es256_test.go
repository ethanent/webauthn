package algorithms

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestES256Verify(t *testing.T) {
	tests := []struct {
		pub     any
		message []byte
		sig     []byte

		verifyExpectHashed string
		verifyReturns      bool

		expect error
	}{
		{
			pub:           &ecdsa.PublicKey{},
			message:       []byte("hello"),
			sig:           []byte("sig"),
			verifyReturns: true,
			expect:        nil,
		},
		{
			pub:           &ecdsa.PublicKey{},
			message:       []byte("hello2"),
			sig:           []byte("sig2"),
			verifyReturns: false,
			expect:        ErrVerificationFailed,
		},
		{
			pub:           &rsa.PublicKey{},
			verifyReturns: false,
			expect:        ErrUnsupportedKeyType,
		},
	}

	e := &ES256{}

	for _, test := range tests {
		ecdsaVerifyASN1 = func(*ecdsa.PublicKey, []byte, []byte) bool {
			return test.verifyReturns
		}
		err := e.Verify(test.pub, test.message, test.sig)
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
