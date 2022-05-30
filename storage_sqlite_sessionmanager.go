package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/pardot/oidc/core"
)

/* This file contains the implementation of the oidc core library session manager interface */

var _ core.SessionManager = (*storage)(nil)

// NewID should return a new, unique identifier to be used for a session. It
// should be hard to guess/brute force
func (s *storage) NewID() string {
	return uuid.NewString()
}

// GetSession should return the current session state for the given session
// ID. It should be deserialized/written in to into. If the session does not
// exist, found should be false with no error.
func (s *storage) GetSession(ctx context.Context, sessionID string, into core.Session) (found bool, err error) {
	var sessdata []byte
	if err := s.db.QueryRowContext(ctx, `
	select oidcstate from sessions
	where id = $1`,
		sessionID).Scan(&sessdata); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("error getting session %s: %w", sessionID, err)
	}

	if err := json.Unmarshal(sessdata, into); err != nil {
		return false, fmt.Errorf("unmarshaling session %s: %w", sessionID, err)
	}

	return true, nil
}

// PutSession should persist the new state of the session
func (s *storage) PutSession(ctx context.Context, session core.Session) error {
	b, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshaling session %s: %w", session.ID(), err)
	}
	if _, err := s.db.ExecContext(ctx,
		`insert into sessions(id, oidcstate, expires_at) values ($1, $2, $3)
		on conflict(id) do update
		set oidcstate=$4, expires_at=$5`,
		session.ID(), b, session.Expiry(), b, session.Expiry()); err != nil {
		return fmt.Errorf("upserting session %s: %w", session.ID(), err)
	}
	return nil
}

// DeleteSession should remove the corresponding session.
func (s *storage) DeleteSession(ctx context.Context, sessionID string) error {
	if _, err := s.db.ExecContext(ctx, `delete from sessions where id=$1`, sessionID); err != nil {
		return fmt.Errorf("deleting session %s: %w", sessionID, err)
	}
	return nil
}
