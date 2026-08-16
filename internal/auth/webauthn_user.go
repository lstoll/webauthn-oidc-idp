package auth

import (
	"context"
	"fmt"
	"uuid"

	"github.com/go-webauthn/webauthn/webauthn"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

type WebAuthnUser struct {
	user        *config.User
	webAuthnID  []byte
	credentials []webauthn.Credential
}

// NewWebAuthnUser creates a WebAuthn user for registration.
func NewWebAuthnUser(user *config.User, passkeyUserID string, credentials []webauthn.Credential) *WebAuthnUser {
	id := []byte(passkeyUserID)
	if len(id) == 0 && user.WebauthnHandle != uuid.Nil() {
		id = user.WebauthnHandle[:]
	}
	return &WebAuthnUser{
		user:        user,
		webAuthnID:  id,
		credentials: credentials,
	}
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.webAuthnID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.user.FullName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (a *Authenticator) NewDiscoverableUserHandler(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		cfgUser, err := a.lookupUser(userHandle)
		if err != nil {
			return nil, err
		}

		var creds []webauthn.Credential
		a.CredStore.Read(func(cs *storage.CredentialStore) {
			creds = cs.WebAuthnCredentials(cfgUser.ID)
		})

		return &WebAuthnUser{
			user:        cfgUser,
			webAuthnID:  userHandle,
			credentials: creds,
		}, nil
	}
}

func (a *Authenticator) lookupUser(userHandle []byte) (*config.User, error) {
	var accountID uuid.UUID
	var found bool
	a.CredStore.Read(func(cs *storage.CredentialStore) {
		accountID, found = cs.LookupAccountByHandle(userHandle)
	})
	if found {
		return a.Config.Users.GetUser(accountID)
	}

	// Legacy handles that have not yet been recorded as aliases.
	if len(userHandle) == 16 && ((userHandle[6]&0xf0)>>4) == 4 {
		var handle uuid.UUID
		copy(handle[:], userHandle)
		return a.Config.Users.GetUserByWebauthnHandle(handle)
	}
	if parsed, err := uuid.Parse(string(userHandle)); err == nil {
		return a.Config.Users.GetUser(parsed)
	}
	for _, u := range a.Config.Users {
		if os, ok := u.Metadata["overrideSubject"].(string); ok && os == string(userHandle) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}
