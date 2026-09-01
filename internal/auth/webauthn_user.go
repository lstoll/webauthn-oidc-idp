package auth

import (
	"fmt"
	"uuid"

	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

// lookupUser resolves a WebAuthn user.id to a config user.
//
// userID is the value from passkey.Response.UnauthenticatedUserID: a Go
// string holding the authenticator's user.id bytes, which may not be UTF-8.
func (a *Authenticator) lookupUser(userID string) (*config.User, error) {
	handle := []byte(userID)

	var accountID uuid.UUID
	var found bool
	a.CredStore.Read(func(cs *storage.CredentialStore) {
		accountID, found = cs.LookupAccountByHandle(handle)
	})
	if found {
		return a.Config.Users.GetUser(accountID)
	}

	// Legacy handles that have not yet been recorded as aliases.
	if len(handle) == 16 && ((handle[6]&0xf0)>>4) == 4 {
		var h uuid.UUID
		copy(h[:], handle)
		return a.Config.Users.GetUserByWebauthnHandle(h)
	}
	if parsed, err := uuid.Parse(userID); err == nil {
		return a.Config.Users.GetUser(parsed)
	}
	for _, u := range a.Config.Users {
		if os, ok := u.Metadata["overrideSubject"].(string); ok && os == userID {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}
