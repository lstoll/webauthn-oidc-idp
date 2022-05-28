package main

import (
	"context"

	"github.com/pardot/oidc/core"
	uuid "github.com/satori/go.uuid"
)

/* This file contains the implementation of the oidc core library session manager interface */

var _ core.SessionManager = (*storage)(nil)

// NewID should return a new, unique identifier to be used for a session. It
// should be hard to guess/brute force
func (s *storage) NewID() string {
	return uuid.NewV4().String()
}

// GetSession should return the current session state for the given session
// ID. It should be deserialized/written in to into. If the session does not
// exist, found should be false with no error.
func (s *storage) GetSession(ctx context.Context, sessionID string, into core.Session) (found bool, err error) {
	panic("TODO")
}

// PutSession should persist the new state of the session
func (s *storage) PutSession(context.Context, core.Session) error {
	panic("TODO")
}

// DeleteSession should remove the corresponding session.
func (s *storage) DeleteSession(ctx context.Context, sessionID string) error {
	panic("TODO")
}
