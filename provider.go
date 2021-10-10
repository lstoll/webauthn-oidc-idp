package main

import (
	"context"
	"html/template"
	"net/http"

	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
)

// Authentication
type Authentication struct {
	// TODO the below probably applies here too. ACR/AMR are definitely not a
	// provider concern, unclear if scopes even are. At the end of the day a
	// providers only real goal is to just say "yep i confirmed who this is"
	*core.Authorization
	// TODO claims probably isn't the correct data type to bubble up here - the
	// provider doesn't really control a bunch of the fields. Think a bit about
	// what we really want, and implement a subset.
	Claims oidc.Claims
}

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
	Authenticate(w http.ResponseWriter, req *http.Request, sessionID string, auth *Authentication)
}

type Provider interface {
	// Initialize is called before the provider is used, to pass it an
	// AuthSessionManager. It should hold on to this, and use it during flow
	// execution.
	Initialize(asm AuthSessionManager) error
	// LoginPanel is called to provide HTML to be rendered in to the login
	LoginPanel(r *http.Request, ar *core.AuthorizationRequest) (template.HTML, error)
}
