package validation

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethanent/webauthn/algorithms"
)

var ErrUnsupportedCOSEAlgorithm = errors.New("unsupported COSE algorithm")

// Verifier is a generic container for a supported public key that allows for
// verification of signatures using common COSE algorithms.
//
// Warning: Further checks must be performed aside from verification of
// signatures.
//
// It supports the algorithms implemented in the algorithms package.
type Verifier struct {
	alg algorithms.COSEAlgorithm
	key any
}

// NewVerifier returns a new Verifier which uses the provided public key and
// identified COSE algorithm. An error will be returned if the algorithm isn't
// supported or the key is an incorrect type for the algorithm.
func NewVerifier(pub any, algorithmValue int) (*Verifier, error) {
	alg, ok := algorithms.Algorithms()[algorithmValue]
	if !ok {
		return nil, ErrUnsupportedCOSEAlgorithm
	}
	if err := alg.CheckKeyType(pub); err != nil {
		return nil, fmt.Errorf("while validating public key for alg %d: %w", alg.Value(), err)
	}
	return &Verifier{
		alg: alg,
		key: pub,
	}, nil
}

// Alg returns the COSE algorithm value the Verifier is using.
func (v *Verifier) Alg() int {
	return v.alg.Value()
}

// verifyMessage uses the internally held public key to verify the message
// using sig.
func (v *Verifier) verifyMessage(message, sig []byte) error {
	return v.alg.Verify(v.key, message, sig)
}

// VerifyAssertionResponse confirms whether the internally held key verifies
// the provided raw Authenticator Data and ClientDataJSON using sig.
func (v *Verifier) VerifyAssertionResponse(authenticatorData, clientDataJSON, sig []byte) error {
	clientDataJSONHash := sha256.Sum256(clientDataJSON)
	d := authenticatorData
	d = append(d, clientDataJSONHash[:]...)
	return v.verifyMessage(d, sig)
}
