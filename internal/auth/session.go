package auth

import (
	"context"
	"time"
	"uuid"

	"lds.li/passidp/internal/appsession"
)

const authFlowValidFor = 10 * time.Minute

// UserIDFromContext returns the logged in user from the session accessible in
// the context.
func UserIDFromContext(ctx context.Context) (*uuid.UUID, bool) {
	as := appsession.FromContext(ctx).Get().Auth
	if as.LoggedInUserID == nil {
		return nil, false
	}
	if time.Now().After(as.ExpiresAt) {
		return nil, false
	}
	return as.LoggedInUserID, true
}

// AuthTimeFromContext returns when the user last actively authenticated.
func AuthTimeFromContext(ctx context.Context) (time.Time, bool) {
	as := appsession.FromContext(ctx).Get().Auth
	if as.LoggedInUserID == nil {
		return time.Time{}, false
	}
	if time.Now().After(as.ExpiresAt) {
		return time.Time{}, false
	}
	if as.AuthenticatedAt.IsZero() {
		return time.Time{}, false
	}
	return as.AuthenticatedAt, true
}
