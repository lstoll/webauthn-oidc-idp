package main

import (
	"context"

	"github.com/pardot/oidc/core"
)

type Storage interface {
	core.SessionManager
	WebauthnUserStore
	Authenticate(ctx context.Context, sessionID string, auth Authentication) error
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
}
