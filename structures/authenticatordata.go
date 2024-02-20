package structures

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// AuthenticatorData contains and allows reading of authenticator data.
// See: https://www.w3.org/TR/webauthn-2/#authenticator-data
type AuthenticatorData struct {
	d []byte
}

func NewAuthenticatorData(d []byte) (*AuthenticatorData, error) {
	if len(d) < 37 {
		return nil, errors.New("invalid AuthenticatorData")
	}
	return &AuthenticatorData{
		d: d,
	}, nil
}

func (a *AuthenticatorData) String() string {
	return fmt.Sprintf(`AuthenticatorData {
	RPIDHash: %v
	Flags:
		0 (UP): %t
		1: %t
		2 (UV): %t
		3 (BE): %t
		4 (BS): %t
		5: %t
		6 (AT): %t
		7 (ED): %t
	SignCount: %d
}`, a.RPIDHash(), a.UP(), a.Flag(1), a.UV(), a.BE(), a.BS(), a.Flag(5), a.AT(), a.ED(), a.SignCount())
}

// RPIDHash is the SHA256 hash of the Relying Party's ID.
func (a *AuthenticatorData) RPIDHash() []byte {
	return a.d[0:32]
}

// UP indicates whether the user is present.
func (a *AuthenticatorData) UP() bool {
	return a.Flag(0)
}

// UV indicates whether the user is verified.
func (a *AuthenticatorData) UV() bool {
	return a.Flag(2)
}

// BE indicates whether the credential source is backup eligible.
func (a *AuthenticatorData) BE() bool {
	return a.Flag(3)
}

// BS indicates whether the credential source is backed up.
func (a *AuthenticatorData) BS() bool {
	return a.Flag(4)
}

// AT indicates whether authenticator data is included.
func (a *AuthenticatorData) AT() bool {
	return a.Flag(6)
}

// ED indicates whether extension data is included.
func (a *AuthenticatorData) ED() bool {
	return a.Flag(7)
}

func (a *AuthenticatorData) SignCount() int {
	return int(binary.BigEndian.Uint32(a.d[33:37]))
}

func (a *AuthenticatorData) Flag(i int) bool {
	return (a.d[32]>>i)&0x01 == 1
}

// RPIDHash returns an RPIDHash for the given RP ID. This may be used when
// comparing AuthenticatorData RPIDHash to a known RP ID.
func RPIDHash(rpID string) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	return rpIDHash[:]
}
