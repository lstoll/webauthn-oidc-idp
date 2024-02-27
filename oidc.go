package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"crawshaw.dev/jsonfile"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	"github.com/google/uuid"
	"github.com/lstoll/oidc/core"
)

// oidcSigner implements core.Signer for a static signing key.
// This is temporary, it will be updated to wrap a keyset stored in DB later.
type oidcSigner struct {
	key RSAKey
}

func (s *oidcSigner) SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error) {
	return jose.RS256, nil
}

func (s *oidcSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: &jose.JSONWebKey{
				Algorithm: string(jose.RS256),
				Key:       cryptosigner.Opaque(s.key),
				KeyID:     s.key.KeyID,
				Use:       "sig",
			},
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	sg, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}

	ser, err := sg.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("serialize signed data: %w", err)
	}
	return []byte(ser), nil
}

func (s *oidcSigner) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %v", err)
	}

	var ok bool
	for _, sig := range jws.Signatures {
		if sig.Header.KeyID == s.key.KeyID {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("signature does not match signing key")
	}

	payload, err := jws.Verify(s.key.Public())
	if err != nil {
		return nil, fmt.Errorf("verify JWT: %w", err)
	}

	return payload, nil
}

// staticKeySource implements discovery.KeySource for a static signing key.
// This is temporary, it will be updated to wrap a keyset later.
type staticKeySource struct {
	key RSAKey
}

func (s *staticKeySource) PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     s.key.KeyID,
				Key:       s.key.Public(),
				Use:       "sig",
				Algorithm: string(jose.RS256),
			},
		},
	}, nil
}

// sessionManager implements core.SessionManager by wrapping a DB.
type sessionManager struct {
	f *jsonfile.JSONFile[schema]
}

func (m *sessionManager) NewID() string {
	return uuid.NewString()
}

func (m *sessionManager) GetSession(_ context.Context, sessionID string, into core.Session) (bool, error) {
	var (
		ok bool
		v  json.RawMessage
	)
	m.f.Read(func(db *schema) {
		v, ok = db.OIDCSessions[sessionID]
	})
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(v, into); err != nil {
		return false, fmt.Errorf("unmarshal session %s into core.Session: %w", sessionID, err)
	}
	return true, nil
}

func (m *sessionManager) PutSession(_ context.Context, session core.Session) error {
	b, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session %s: %w", session.ID(), err)
	}
	return m.f.Write(func(db *schema) error {
		if db.OIDCSessions == nil {
			db.OIDCSessions = make(map[string]json.RawMessage)
		}
		db.OIDCSessions[session.ID()] = b
		return nil
	})
}

func (m *sessionManager) DeleteSession(_ context.Context, sessionID string) error {
	return m.f.Write(func(db *schema) error {
		delete(db.OIDCSessions, sessionID)
		return nil
	})
}
