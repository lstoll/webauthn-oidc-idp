package webauthn

import (
	"github.com/koesie10/webauthn/webauthn"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
)

var _ webauthn.AuthenticatorStore = (*storage)(nil)

type storage struct {
	ua UserAuthenticator
}

// AddAuthenticator should add the given authenticator to a user. The authenticator's type should not be depended
// on; it is constructed by this package. All information should be stored in a way such that it is retrievable
// in the future using GetAuthenticator and GetAuthenticators.
func (s *storage) AddAuthenticator(user webauthn.User, authenticator webauthn.Authenticator) error {
	a := &idppb.WebauthnAuthenticator{
		UserId:       string(user.WebAuthID()),
		Id:           authenticator.WebAuthID(),
		CredentialId: authenticator.WebAuthCredentialID(),
		PublicKey:    authenticator.WebAuthPublicKey(),
		Aaguid:       authenticator.WebAuthAAGUID(),
		SignCount:    authenticator.WebAuthSignCount(),
	}
	if err := s.ua.AddAuthenticatorToUser(string(user.WebAuthID()), a); err != nil {
		return errors.Wrap(err, "Error adding authenticator to user")
	}
	return nil
}

// GetAuthenticator gets a single Authenticator by the given id, as returned by Authenticator.WebAuthID.
func (s *storage) GetAuthenticator(id []byte) (webauthn.Authenticator, error) {
	auth, err := s.ua.GetAuthenticator(id)
	if err != nil {
		return nil, errors.Wrap(err, "Error fetching authenticator")
	}
	return &authenticator{WebauthnAuthenticator: auth}, nil
}

// GetAuthenticators gets a list of all registered authenticators for this user. It might be the case that the user
// has been constructed by this package and the only non-empty value is the WebAuthID. In this case, the store
// should still return the authenticators as specified by the ID.
func (s *storage) GetAuthenticators(user webauthn.User) ([]webauthn.Authenticator, error) {
	auths, err := s.ua.UserAuthenticators(string(user.WebAuthID()))
	if err != nil {
		return nil, errors.Wrap(err, "Error getting authenticator")
	}
	var ret []webauthn.Authenticator
	for _, a := range auths {
		ret = append(ret, &authenticator{WebauthnAuthenticator: a})
	}
	return ret, nil
}

var (
	_ webauthn.User          = (*user)(nil)
	_ webauthn.Authenticator = (*authenticator)(nil)
)

type user struct {
	*idppb.WebauthnUser
}

type authenticator struct {
	*idppb.WebauthnAuthenticator
}

func (u *user) WebAuthID() []byte {
	return []byte(u.Id)
}

func (u *user) WebAuthName() string {
	return u.Name
}

func (u *user) WebAuthDisplayName() string {
	return u.Name
}

func (a *authenticator) WebAuthID() []byte {
	return a.Id
}

func (a *authenticator) WebAuthCredentialID() []byte {
	return a.CredentialId
}

func (a *authenticator) WebAuthPublicKey() []byte {
	return a.PublicKey
}

func (a *authenticator) WebAuthAAGUID() []byte {
	return a.Aaguid
}

func (a *authenticator) WebAuthSignCount() uint32 {
	return a.SignCount
}
