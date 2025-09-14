package oidcsvr

import (
	"context"

	"github.com/google/uuid"
	"lds.li/oauth2ext/oauth2as"
)

// Storage is the interface for storing and retrieving grants.
// This is a local interface that matches oauth2as.Storage for documentation purposes.
type Storage interface {
	// CreateGrant creates a new grant.
	CreateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error
	// UpdateGrant updates an existing grant.
	UpdateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error
	// ExpireGrant expires a grant.
	ExpireGrant(ctx context.Context, id uuid.UUID) error
	// GetGrant retrieves a grant by ID. If no grant is found, it should return
	// a nil grant.
	GetGrant(ctx context.Context, id uuid.UUID) (*oauth2as.StoredGrant, error)
	// GetGrantByAuthCode retrieves a grant by authorization code. If no grant
	// is found, it should return a nil grant.
	GetGrantByAuthCode(ctx context.Context, authCode string) (*oauth2as.StoredGrant, error)
	// GetGrantByRefreshToken retrieves a grant by refresh token. If no grant
	// is found, it should return a nil grant.
	GetGrantByRefreshToken(ctx context.Context, refreshToken string) (*oauth2as.StoredGrant, error)
}
