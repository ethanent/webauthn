package validation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/ethanent/webauthn/structures"
)

// Policy validates AuthenticatorData and CredentialData using RP information
// and requirements.
//
// Warning: Be sure to verify data using a Verifier, and be aware that
// additional outside checks are necessary too.
//
// Do not change Policy field values after initialization as some are cached
// internally.
type Policy struct {
	RPID             string
	PermitOrigins    []string
	PermitTopOrigins []string

	PermitCrossOrigin bool
	RequireUV         bool

	mux sync.RWMutex

	initialized         bool
	rpIDHash            []byte
	permittedOrigins    map[string]struct{}
	permittedTopOrigins map[string]struct{}
}

func (r *Policy) ensureInitialized() {
	r.mux.RLock()
	if r.initialized {
		r.mux.RUnlock()
		return
	}
	r.mux.RUnlock()
	r.mux.Lock()
	defer r.mux.Unlock()
	rpIDHash := sha256.Sum256([]byte(r.RPID))
	r.rpIDHash = rpIDHash[:]
	r.permittedOrigins = map[string]struct{}{}
	for _, o := range r.PermitOrigins {
		r.permittedOrigins[o] = struct{}{}
	}
	r.permittedTopOrigins = map[string]struct{}{}
	for _, o := range r.PermitTopOrigins {
		r.permittedTopOrigins[o] = struct{}{}
	}
	r.initialized = true
}

// CheckCredentialID confirms that the credential ID is valid.
func (r *Policy) CheckCredentialID(credID []byte) error {
	r.ensureInitialized()
	if len(credID) > 1023 {
		return fmt.Errorf("invalid size for credential ID")
	}
	return nil
}

// CheckAD confirms that the AuthenticatorData is in line with the RPOptions
// and partially validates it.
//
// If checking AD during a registration (attestation), you may set
// lastSignCount to 0.
func (r *Policy) CheckAD(ad *structures.AuthenticatorData, lastSignCount int) error {
	r.ensureInitialized()
	if !bytes.Equal(ad.RPIDHash(), r.rpIDHash) {
		return errors.New("AuthenticatorData is for the wrong RP (incorrect RP ID Hash)")
	}
	if !ad.UP() {
		return errors.New("AuthenticatorData UP bit not set (no user present)")
	}
	if r.RequireUV && !ad.UV() {
		return errors.New("AuthenticatorData UV bit not set (user not verified)")
	}
	if lastSignCount == 0 && ad.SignCount() == 0 {
		return nil
	}
	if ad.SignCount() <= lastSignCount {
		return errors.New("SignCount decreased, indicating a cloned key")
	}
	return nil
}

// CheckCD confirms that the ClientData is in line with the RPOptions and
// partially validates it.
//
// Note that validating the Challenge is still required.
func (r *Policy) CheckCD(cd *structures.ClientData, isAttestation bool) error {
	r.ensureInitialized()
	expectType := "webauthn.get"
	if isAttestation {
		expectType = "webauthn.create"
	}
	if cd.Type != expectType {
		return fmt.Errorf("ClientData.Type is '%s', expected '%s'", cd.Type, expectType)
	}
	if _, originOK := r.permittedOrigins[cd.Origin]; !originOK {
		return errors.New("ClientData.Origin is not an expected origin")
	}
	if cd.TopOrigin == "" && !cd.CrossOrigin {
		return nil
	}
	if !r.PermitCrossOrigin {
		return errors.New("cross origin attestation / assertion is not permitted")
	}
	if _, topOriginOK := r.permittedTopOrigins[cd.TopOrigin]; !topOriginOK {
		return errors.New("ClientData.TopOrigin is not a permitted top origin")
	}
	return nil
}
