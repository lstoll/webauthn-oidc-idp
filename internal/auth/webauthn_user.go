package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type webauthnUser struct {
	user queries.User
	// overrideID is the ID used for the webauthn user, if it differs from the
	// user ID.
	overrideID  []byte
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return u.overrideID
}

func (u *webauthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.user.FullName
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (a *Authenticator) NewDiscoverableUserHandler(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		var qu queries.User
		var validateID []byte

		// this handles a variety of userHandle formats, that we've used over
		// time. if we ever clean things up it would be nice to remove some of
		// the fallbacks.

		// If the userHandle is a valid UUID4 in bytes, use it directly
		if len(userHandle) == 16 && ((userHandle[6]&0xf0)>>4) == 4 {
			// it's a UUID4, likely the distinct webauthn handle
			handle, err := uuid.FromBytes(userHandle)
			if err != nil {
				return nil, fmt.Errorf("invalid UUIDv4: %w", err)
			}
			qu, err = a.Queries.GetUserByWebauthnHandle(ctx, handle)
			if err != nil {
				return nil, fmt.Errorf("getting user by webauthn handle: %w", err)
			}
			validateID = qu.WebauthnHandle[:]
		} else if err := uuid.Validate(string(userHandle)); err == nil {
			// string UUID, likely the user ID
			qu, err = a.Queries.GetUser(ctx, uuid.MustParse(string(userHandle)))
			if err != nil {
				return nil, fmt.Errorf("getting user by ID: %w", err)
			}
			validateID = []byte(qu.ID.String())
		} else {
			// process it as a fallback subject.
			qu, err = a.Queries.GetUserByOverrideSubject(ctx, sql.NullString{String: string(userHandle), Valid: true})
			if err != nil {
				return nil, fmt.Errorf("getting user by override subject: %w", err)
			}
			validateID = []byte(qu.OverrideSubject.String)
		}

		// Get user credentials
		creds, err := a.Queries.GetUserCredentials(ctx, qu.ID)
		if err != nil {
			return nil, fmt.Errorf("getting user credentials: %w", err)
		}

		wu := &webauthnUser{
			user:       qu,
			overrideID: validateID,
		}
		for _, c := range creds {
			var cred webauthn.Credential
			if err := json.Unmarshal(c.CredentialData, &cred); err != nil {
				return nil, fmt.Errorf("unmarshalling credential: %w", err)
			}
			wu.credentials = append(wu.credentials, cred)
		}

		return wu, nil
	}
}
