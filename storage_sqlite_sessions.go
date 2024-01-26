package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

var _ webSessionStore = (*storage)(nil)

// mustNewSessionID generates a new 256bit random ID, base62 encoded. It will
// panic if the random read fails.
func mustNewSessionID() string {
	id := make([]byte, 32)
	if r, err := io.ReadFull(rand.Reader, id); err != nil || r != 32 {
		panic(fmt.Sprintf("wanted 32 random bytes, read %d with err %v", r, err))
	}
	var i big.Int
	i.SetBytes(id[:])
	return i.Text(62)
}

// GetWebSession returns the session for the given ID. if no session, ok will be
// false.
func (s *storage) GetWebSession(ctx context.Context, key string) (sess *webSession, ok bool, err error) {
	var (
		data      []byte
		expiresAt time.Time
	)
	if err := s.db.QueryRowContext(ctx, `select data, expires_at from web_sessions where key = $1 and expires_at > $2`, key, time.Now()).Scan(&data, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("getting session %s: %w", key, err)
	}
	var w webSession
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, false, fmt.Errorf("unmarshaling session %s: %w", key, err)
	}
	w.SessionID = key
	// TODO - expires at?
	return &w, true, nil
}

// CreateWebSession returns a new, unpersisted session for use
func (s *storage) CreateWebSession(_ context.Context) (*webSession, error) {
	return &webSession{
		SessionID: mustNewSessionID(),
	}, nil
}

// PutWebSession persists the given session
func (s *storage) PutWebSession(ctx context.Context, sess *webSession, validFor time.Duration) error {
	if sess.SessionID == "" {
		return errors.New("cannot persist a session with no ID")
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshaling session %s: %v", sess.SessionID, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`insert into web_sessions (key, data, expires_at, updated_at) values ($1, $2, $3, $4)
		on conflict(key) do update set data=$5, expires_at=$6, updated_at=$7
		`, sess.SessionID, data, time.Now().Add(validFor), time.Now(),
		data, time.Now().Add(validFor), time.Now()); err != nil {
		return fmt.Errorf("putting data for %s: %w", sess.SessionID, err)
	}
	return nil
}

// DeleteWebSession removes the session for the given ID.
func (s *storage) DeleteWebSession(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx,
		`delete from web_sessions where key=$1
		`, key); err != nil {
		return fmt.Errorf("deleting session %s: %w", key, err)
	}
	return nil
}
