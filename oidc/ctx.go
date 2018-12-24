package oidcserver

import (
	"context"

	"github.com/lstoll/idp"
)

type contextKey string

func (c contextKey) String() string {
	return "server context key " + string(c)
}

var (
	contextKeyAuthRequestID = contextKey("auth-request-id")
	contextKeyIdentity      = contextKey("identity")
)

// AuthRequestID gets the authorization request ID from the context.
func AuthRequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKeyAuthRequestID).(string)
	return id, ok
}

// Identity returns the authorized identity.
func Identity(ctx context.Context) (idp.Identity, bool) {
	id, ok := ctx.Value(contextKeyIdentity).(idp.Identity)
	return id, ok
}
