package webauthn

import "github.com/lstoll/idp/idppb"

// UserAuthenticator is used to communicate with the external service that
// validates users
type UserAuthenticator interface {
	// LoginUser should return a User object if username and password are
	// correct
	LoginUser(username, password string) (*idppb.WebauthnUser, error)
	// GetUser returns the user for the given ID
	GetUser(id string) (*idppb.WebauthnUser, error)
	// Look up a user by their username
	GetUserByUsername(username string) (*idppb.WebauthnUser, error)
	// AddAuthenticatorToUser should associate the given user with the given
	// authenticator
	AddAuthenticatorToUser(userID string, authenticator *idppb.WebauthnAuthenticator) error
	// UserAuthenticators should return all the authenticators registered to the
	// given user
	UserAuthenticators(userID string) ([]*idppb.WebauthnAuthenticator, error)
	// GetAuthenticator returns the authenticator matching the provided ID
	GetAuthenticator(id []byte) (*idppb.WebauthnAuthenticator, error)
}
