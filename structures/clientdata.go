package structures

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type ClientData struct {
	Type         string `json:"type"`
	Challenge    []byte
	ChallengeRaw string `json:"challenge"`
	Origin       string `json:"origin"`
	TopOrigin    string `json:"topOrigin"`
	CrossOrigin  bool   `json:"crossOrigin"`
}

// NewClientData parses a clientDataJSON []byte, returning a client data
// instance.
func NewClientData(clientDataJSON []byte) (*ClientData, error) {
	c := &ClientData{}
	if err := json.Unmarshal(clientDataJSON, c); err != nil {
		return nil, fmt.Errorf("invalid JSON data in clientDataJSON: %w", err)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(c.ChallengeRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url data in clientDataJSON: %w", err)
	}
	c.Challenge = challenge
	return c, nil
}
