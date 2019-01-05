package idp

import (
	"net/http"

	"github.com/crewjam/saml"
	"github.com/gorilla/sessions"
	"github.com/lstoll/idp/idppb"
)

// Authenticator can be used by connectors to access metadata about the identity
// backend, and to mark an authentication flow as successful.
type Authenticator interface {
	// Authenticate should be called on a successful authentication flow to set
	// the desired identity for the flow ID. The user should then be redirected
	// to returned URL to complete the flow
	Authenticate(authID string, ident idppb.Identity) (returnURL string, err error)
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
	// OIDCClient is called to find the details for a given OIDC Client ID. If a
	// client is found, the details should be returned with ok true. If it
	// doesn't exist, ok should be false.
	OIDCClient(clientID string) (client *idppb.OIDCClient, ok bool, err error)
	// SAMLServiceProvider is called to get information about the given SAML
	// provider ID
	SAMLServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error)
}

// Storage is used for maintaining the persistent state of the provider
type Storage interface {
	Put(namespace, key string, data []byte) error
	Get(namespace, key string) ([]byte, error)
	// List iterates all items in the namespace, calling batchFunc in batches of
	// items. if batchFunc returns false, the list is terminated
	List(namespace string, batchFunc func(map[string][]byte) bool) error
	Delete(namespace, key string) error
	// When passed an error, returns true if it occured because the given item
	// wasn't found, or false if it was for any other reason.
	ErrIsNotFound(error) bool
}
