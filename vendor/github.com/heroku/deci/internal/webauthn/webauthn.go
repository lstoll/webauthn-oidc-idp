package webauthn

import (
	"crypto/rand"
)

const (
	challengeBytesLength = 32
)

func NewChallenge() ([]byte, error) {
	challenge := make([]byte, challengeBytesLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}
