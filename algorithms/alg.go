package algorithms

import (
	"errors"
)

var ErrUnsupportedKeyType = errors.New("the type of key provided is not supported by the algorithm")

// COSEAlgorithm implementers provide functions for using public keys to verify
// data signed using standard COSE algorithms.
//
// See the algorithm definitions:
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
type COSEAlgorithm interface {
	// Value returns the COSE algorithm value for the algorithm.
	Value() int

	// CheckKeyType checks that the public key is the correct type for the
	// algorithm, returning an error if not.
	CheckKeyType(key any) error

	// Verify uses the public key to perform a verification of the message data
	// using sig, returning whether the verification succeeded.
	Verify(key any, message, sig []byte) (bool, error)
}

var algs = []COSEAlgorithm{
	&RS256{},
	&ES256{},
	&EdDSA{},
}

// Algorithms returns the implemented COSE algorithms by COSE algorithm value.
func Algorithms() map[int]COSEAlgorithm {
	m := map[int]COSEAlgorithm{}
	for _, alg := range algs {
		m[alg.Value()] = alg
	}
	return m
}
