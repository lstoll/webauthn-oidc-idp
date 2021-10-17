package main

import (
	"context"
	"html/template"
	"net/http"

	"github.com/pardot/oidc/core"
)

// Authentication are the details flagged for an authenticated user of the
// system.
type Authentication struct {
	// Subject (required) is the unique identifier for the authenticated user.
	// This should be stable over time.
	Subject string `dynamodbav:"subject"`
	// EMail (optional), for when the email/profile scope is requested
	EMail string `dynamodbav:"email,omitempty"`
	// FullName (optional), for when the profile scope is requested
	FullName string `dynamodbav:"full_name,omitempty"`
	// Groups (optional), for when the groups scope is requested
	Groups []string `dynamodbav:"groups,omitempty"`
	// ExtraClaims (optional) fields to add to the returned ID token claims
	ExtraClaims map[string]interface{} `dynamodbav:"extra_claims,omitempty"`
	// PolicyContext is internal data, that is passed to the policies that are
	// evaluated downstream. This data is not presented to the user.
	PolicyContext map[string]interface{} `dynamodbav:"policy_context,omitempty"`
}

// AuthSessionManager is responsible for managing an auth session throughout
// it's lifecycle, from the moment a user decides to authenticate via us until
// the credentials expire or are revoked. This is essentially a companion of
// github.com/pardot/oidc/core/SessionManager , for tracking our application
// specific items. It can associate and retrieve relevant metadata with a
// session. In addition, it can mark a session as authenticated, moving it from
// the gathering user info stage in to the tokens issued/refreshed stage.
type AuthSessionManager interface {
	// GetMetadata retrieves provider-specific metadata for the given session in
	// to the provided json-compatible object. If no metadata is found, ok will
	// be false.
	GetMetadata(ctx context.Context, sessionID string, into interface{}) (ok bool, err error)
	// PutMetadata stores the json-marshalable, provider specific data
	// associated with the given session.
	PutMetadata(ctx context.Context, sessionID string, d interface{}) error

	// Authenticate should be called at the end of the providers authentication
	// flow, to provide details about who was authenticated for the sesion. This
	// should be passed the http request and non-started response, it will
	// handle the next steps.
	Authenticate(w http.ResponseWriter, req *http.Request, sessionID string, auth Authentication)
	// GetAuthentication returns the authentication details for a sesion, if
	// authenticated
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
}

// Provider is used to authenticate users.
type Provider interface {
	// ID returns the unique identifier for this provider instance
	ID() string
	// ACRValues returns the ACR value this provider satisfies
	ACR() string
	// AMR returns the amr for this provider
	AMR() string
	// LoginPanel is called to provide HTML to be rendered in to the login page
	LoginPanel(r *http.Request, ar *core.AuthorizationRequest) (template.HTML, error)
}
