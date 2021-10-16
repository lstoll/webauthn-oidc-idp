package main

import (
	"context"

	"github.com/pardot/oidc/core"
)

type Storage interface {
	core.SessionManager
	WebauthnUserStore
	GetMetadata(ctx context.Context, sessionID string) (Metadata, bool, error)
	PutMetadata(ctx context.Context, sessionID string, meta Metadata) error
	Authenticate(ctx context.Context, sessionID string, auth Authentication) error
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
}
