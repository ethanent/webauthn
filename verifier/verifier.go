package webauthn

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethanent/webauthn/structures"

	"github.com/ethanent/webauthn/algorithms"
)

var ErrUnsupportedCOSEAlgorithm = errors.New("unsupported COSE algorithm")
var ErrSignatureInvalid = errors.New("signature is invalid")
var ErrInvalidAssertion = errors.New("assertion is invalid")

// Verifier is a generic container for a supported public key that allows for
// verification of signatures of common COSE signature types.
//
// It supports the algorithms implemented in the algorithms package.
type Verifier struct {
	rpIDHash []byte
	alg      algorithms.COSEAlgorithm
	key      any
}

// NewVerifier returns a new Verifier which uses the provided public key,
// identified COSE algorithm, and expected RP ID. An error will be returned if
// the algorithm isn't supported or the key is an incorrect type for the
// algorithm.
func NewVerifier(pub any, algorithmValue int, rpID string) (*Verifier, error) {
	alg, ok := algorithms.Algorithms()[algorithmValue]
	if !ok {
		return nil, ErrUnsupportedCOSEAlgorithm
	}
	if err := alg.CheckKeyType(pub); err != nil {
		return nil, fmt.Errorf("while validating public key for alg %d: %w", alg.Value(), err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	return &Verifier{
		rpIDHash: rpIDHash[:],
		alg:      alg,
		key:      pub,
	}, nil
}

// Alg returns the COSE algorithm value the Verifier is using.
func (v *Verifier) Alg() int {
	return v.alg.Value()
}

// verifyMessage uses the internally held public key to verify the message
// using sig.
func (v *Verifier) verifyMessage(message, sig []byte) (bool, error) {
	return v.alg.Verify(v.key, message, sig)
}

// verifyAssertionResponse concatenates the raw authenticatorData and a hash of
// the raw clientDataJSON and confirms that the internally held public key
// verifies the data with sig.
func (v *Verifier) verifyAssertionResponse(authenticatorData, clientDataJSON, sig []byte) (bool, error) {
	clientDataJSONHash := sha256.Sum256(clientDataJSON)
	d := authenticatorData
	d = append(d, clientDataJSONHash[:]...)
	return v.verifyMessage(d, sig)
}

// VerifyParseAssertion takes the raw authenticatorData, raw clientDataJSON,
// and sig for a credential assertion, and parses and partially verifies the
// data. (W3C WebAuthn spec Section 7.2; steps 11, 15, 16, and 19-20)
//
// Further details about verification:
// https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
func (v *Verifier) VerifyParseAssertion(authenticatorData, clientDataJSON, sig []byte) (*structures.AuthenticatorData, *structures.ClientData, error) {
	verified, err := v.verifyAssertionResponse(authenticatorData, clientDataJSON, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("while verifying assertion response: %w", err)
	}
	if !verified {
		return nil, nil, ErrSignatureInvalid
	}
	ad, err := structures.NewAuthenticatorData(authenticatorData)
	if err != nil {
		return nil, nil, err
	}
	cd, err := structures.NewClientData(clientDataJSON)
	if err != nil {
		return nil, nil, err
	}
	if cd.Type != "webauthn.get" {
		return nil, nil, fmt.Errorf("%w: invalid Type in client data", ErrInvalidAssertion)
	}
	if !bytes.Equal(ad.RPIDHash(), v.rpIDHash) {
		return nil, nil, fmt.Errorf("%w: incorrect RP", ErrInvalidAssertion)
	}
	if !ad.UP() {
		return nil, nil, fmt.Errorf("%w: user is not present", ErrInvalidAssertion)
	}
	return ad, cd, nil
}
