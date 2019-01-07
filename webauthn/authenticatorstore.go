package webauthn

import (
	"context"

	"github.com/koesie10/webauthn/webauthn"
	"github.com/lstoll/idp/storage/storagepb"
	"github.com/pkg/errors"
)

var _ webauthn.AuthenticatorStore = (*storage)(nil)

// storage implements the storage interface the webauthn library expects. This
// is done by wrapping our storage interface.
type storage struct {
	ua storagepb.WebAuthnUserServiceClient
}

// AddAuthenticator should add the given authenticator to a user. The authenticator's type should not be depended
// on; it is constructed by this package. All information should be stored in a way such that it is retrievable
// in the future using GetAuthenticator and GetAuthenticators.
func (s *storage) AddAuthenticator(user webauthn.User, authenticator webauthn.Authenticator) error {
	req := &storagepb.AddAuthenticatorRequest{
		UserId: string(user.WebAuthID()),
		Authenticator: &storagepb.WebauthnAuthenticator{
			UserId:       string(user.WebAuthID()),
			Id:           authenticator.WebAuthID(),
			CredentialId: authenticator.WebAuthCredentialID(),
			PublicKey:    authenticator.WebAuthPublicKey(),
			Aaguid:       authenticator.WebAuthAAGUID(),
			SignCount:    authenticator.WebAuthSignCount(),
		},
	}
	if _, err := s.ua.AddAuthenticatorToUser(context.Background(), req); err != nil {
		return errors.Wrap(err, "Error adding authenticator to user")
	}
	return nil
}

// GetAuthenticator gets a single Authenticator by the given id, as returned by Authenticator.WebAuthID.
func (s *storage) GetAuthenticator(id []byte) (webauthn.Authenticator, error) {
	req := &storagepb.GetAuthenticatorRequest{
		AuthenticatorId: id,
	}
	resp, err := s.ua.GetAuthenticator(context.Background(), req)
	if err != nil {
		return nil, errors.Wrap(err, "Error fetching authenticator")
	}
	return &authenticator{WebauthnAuthenticator: resp.Authenticator}, nil
}

// GetAuthenticators gets a list of all registered authenticators for this user. It might be the case that the user
// has been constructed by this package and the only non-empty value is the WebAuthID. In this case, the store
// should still return the authenticators as specified by the ID.
func (s *storage) GetAuthenticators(user webauthn.User) ([]webauthn.Authenticator, error) {
	req := &storagepb.GetUserRequest{
		Lookup: &storagepb.GetUserRequest_UserId{UserId: string(user.WebAuthID())},
	}
	resp, err := s.ua.UserAuthenticators(context.Background(), req)
	if err != nil {
		return nil, errors.Wrap(err, "Error getting authenticators")
	}
	var ret []webauthn.Authenticator
	for _, a := range resp.Authenticators {
		ret = append(ret, &authenticator{WebauthnAuthenticator: a})
	}
	return ret, nil
}

// Map our implementation to the interfaces webauthn lib expects

var (
	_ webauthn.User          = (*user)(nil)
	_ webauthn.Authenticator = (*authenticator)(nil)
)

type user struct {
	*storagepb.WebauthnUser
}

type authenticator struct {
	*storagepb.WebauthnAuthenticator
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
