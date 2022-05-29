package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

var _ Storage = (*storage)(nil)

func (s *storage) Authenticate(ctx context.Context, sessionID string, auth Authentication) error {
	b, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshaling authentication %s: %w", sessionID, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`update sessions set authentication=$1 where id=$2`,
		b, sessionID); err != nil {
		return fmt.Errorf("updating authentication %s: %w", sessionID, err)
	}
	return nil
}

func (s *storage) GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error) {
	var sessdata []byte
	if err := s.db.QueryRowContext(ctx, `
	select authentication from sessions where id = $1`,
		sessionID).Scan(&sessdata); err != nil {
		if err == sql.ErrNoRows {
			return Authentication{}, false, nil
		}
		return Authentication{}, false, fmt.Errorf("error getting authentication %s: %w", sessionID, err)
	}

	if sessdata == nil && len(sessdata) == 0 {
		return Authentication{}, false, nil
	}

	var a Authentication
	if err := json.Unmarshal(sessdata, &a); err != nil {
		return Authentication{}, false, fmt.Errorf("unmarshaling authentication %s: %w", sessionID, err)
	}

	return a, true, nil
}
