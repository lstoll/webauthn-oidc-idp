package idp

import (
	"net/http"

	"github.com/gorilla/sessions"
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

// Connector is used to actually manage the end user authentication
type Connector interface {
	// Initialize will be called at startup, passing in a handle to the
	// authenticator the connector can interact with.
	Initialize(auth Authenticator) error
	// LoginUrl should return the URL to redirect the user to to complete the
	// login flow. It is passed the ID of this authentication flow, this will
	// be needed to finalize the login process.
	LoginUrl(authID string) (url string, err error)
}

// Storage is used for maintaining the persistent state of the provider
type Storage interface {
	Put(namespace, key string, data []byte) error
	Get(namespace, key string) ([]byte, error)
	Delete(namespace, key string) error
}
