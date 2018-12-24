package idp

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
	jose "gopkg.in/square/go-jose.v2"
)

// Identity represents a user that was authenticated.
type Identity struct {
	// UserID is a unique identifier for this user. It should never change
	UserID string

	// TODO - what is the standard identity object
}

// Authenticator can be used by connectors to access metadata about the identity
// backend, and to mark an authentication flow as successful.
type Authenticator interface {
	// Authenticate should be called on a successful authentication flow to set
	// the desired identity for the flow ID. The user should then be redirected
	// to returned URL to complete the flow
	Authenticate(authID string, ident Identity) (returnURL string, err error)
	// Session store, can be used for connector specific cookie state. Need to
	// call Save() if modified
	Session(r *http.Request) sessions.Store
	// Storage can be used for persistent state
	Storage() Storage
}

// SSOMethod indicates the SSO system the user is being authenticated with
type SSOMethod int

const (
	// SSOMethodSAML indicates this request is part of a SAML flow
	SSOMethodSAML SSOMethod = iota
	// SSOMethodOIDC indicates this request is part of an OpenID Connect flow
	SSOMethodOIDC
)

// LoginRequest encapsulates the information passed in for this SSO request.
type LoginRequest struct {
	// SSOMethod is the SSO system access is being requested for
	SSOMethod SSOMethod
	// AuthID is the unique identifier for this access request. It is assigned
	// at login request, and is needed to finalize the flow.
	AuthID string
	// ClientID is the OAuth2 client for OIDC, or SAML issuer that access is
	// being requested for
	ClientID string
	// Scopes are the Oauth2 Scopes for OIDC requests. SAML has no equivalent.
	Scopes []string
}

// Connector is used to actually manage the end user authentication
type Connector interface {
	// Initialize will be called at startup, passing in a handle to the
	// authenticator the connector can interact with.
	Initialize(auth Authenticator) error
	// LoginPage should render the login page, and kick off the connectors auth
	// flow. This method can render whatever it wants and run the user through
	// any arbitrary intermediate pages. The only requirement is that it threads
	// the AuthID through these, and at the end of the connector flow it needs
	// to pass this to the Authenticator's Authenticate method, and redirect the
	// user to the resulting URL.
	LoginPage(w http.ResponseWriter, r *http.Request, lr LoginRequest)
}

// RefreshConnector can support "refreshing" the authenticated session without
// requiring the user to participate in the process (OIDC)
// TODO -  SAML Passive Authentication?
type RefreshConnector interface {
	Connector
	// Refresh is called when a client attempts to claim a refresh token. The
	// connector should attempt to update the identity object to reflect any
	// changes since the token was last refreshed.
	Refresh(ctx context.Context, scopes []string, identity Identity) (Identity, error)
}

// Storage is used for maintaining the persistent state of the provider
type Storage interface {
	Put(namespace, key string, data []byte) error
	Get(namespace, key string) ([]byte, error)
	Delete(namespace, key string) error
}

// Signer is used for signing JWTs
type Signer interface {
	// SignToken will marshal the provided token to JSON, and sign it with the
	// current signing key.
	SignToken(interface{}) ([]byte, error)
	// PublicKeys returns a list of currently valid public keys this service
	// could have signed a token with.
	PublicKeys() (jose.JSONWebKeySet, error)
}
