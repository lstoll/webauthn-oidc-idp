package main

import (
	"context"

	"github.com/pardot/oidc/core"
)

// Authentication are the details flagged for an authenticated user of the
// system.
type Authentication struct {
	// Subject (required) is the unique identifier for the authenticated user.
	// This should be stable over time.
	Subject string `json:"subject"`
	// EMail (optional), for when the email/profile scope is requested
	EMail string `json:"email,omitempty"`
	// FullName (optional), for when the profile scope is requested
	FullName string `json:"full_name,omitempty"`
	// Groups (optional), for when the groups scope is requested
	Groups []string `json:"groups,omitempty"`
	// ExtraClaims (optional) fields to add to the returned ID token claims
	ExtraClaims map[string]interface{} `json:"extra_claims,omitempty"`
	// PolicyContext is internal data, that is passed to the policies that are
	// evaluated downstream. This data is not presented to the user.
	PolicyContext map[string]interface{} `json:"policy_context,omitempty"`
}

type Storage interface {
	core.SessionManager
	WebauthnUserStore
	Authenticate(ctx context.Context, sessionID string, auth Authentication) error
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
}
