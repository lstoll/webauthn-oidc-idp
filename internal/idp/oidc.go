package idp

import (
	"context"
	"encoding/json"
	"fmt"

	"crawshaw.dev/jsonfile"
	"github.com/google/uuid"
	"github.com/lstoll/oidc/core"
)

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
