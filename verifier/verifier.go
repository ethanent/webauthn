package webauthn

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethanent/webauthn/structures"

	"github.com/ethanent/webauthn/algorithms"
)

var ErrUnsupportedCOSEAlgorithm = errors.New("unsupported COSE algorithm")
var ErrSignatureInvalid = errors.New("signature is invalid")

// Verifier is a generic container for a supported public key that allows for
// verification of signatures of common COSE signature types.
//
// It supports the algorithms implemented in the algorithms package.
type Verifier struct {
	alg algorithms.COSEAlgorithm
	key any
}

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

func (v *Verifier) VerifyMessage(message, sig []byte) (bool, error) {
	return v.alg.Verify(v.key, message, sig)
}

func (v *Verifier) VerifyAssertionResponse(authenticatorData, clientDataJSON, sig []byte) (bool, error) {
	clientDataJSONHash := sha256.Sum256(clientDataJSON)
	d := authenticatorData
	d = append(d, clientDataJSONHash[:]...)
	return v.VerifyMessage(d, sig)
}

func (v *Verifier) VerifyParseAssertionResponse(authenticatorData, clientDataJSON, sig []byte) (*structures.AuthenticatorData, *structures.ClientData, error) {
	verified, err := v.VerifyAssertionResponse(authenticatorData, clientDataJSON, sig)
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
	return ad, cd, nil
}
