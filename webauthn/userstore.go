package webauthn

import (
	"encoding/json"

	"github.com/golang/protobuf/proto"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	userCredsNS     = "user-creds"
	userNS          = "users"
	authenticatorNS = "authenticator"
)

var _ UserAuthenticator = (*UserStore)(nil)

// UserStore is a simple UserAuthenticator implementation backing onto the IDP
// storage interface
type UserStore struct {
	Storage idp.Storage
}

type storeUser struct {
	Password []byte `json:"password"`
	UserID   string `json:"user_id"`
}

// LoginUser should return a User object if username and password are
// correct
func (u *UserStore) LoginUser(username, password string) (*idppb.WebauthnUser, error) {
	ub, err := u.Storage.Get(userCredsNS, username)
	if err != nil {
		return nil, errors.Wrap(err, "Error looking up user by login")
	}
	su := storeUser{}
	if err := json.Unmarshal(ub, &su); err != nil {
		return nil, errors.Wrap(err, "Error unmarshaling user")
	}
	if err := bcrypt.CompareHashAndPassword(su.Password, []byte(password)); err != nil {
		return nil, err
	}

	return u.GetUser(su.UserID)
}

// GetUser returns the user for the given ID
func (u *UserStore) GetUser(id string) (*idppb.WebauthnUser, error) {
	ub, err := u.Storage.Get(userNS, id)
	if err != nil {
		return nil, errors.Wrapf(err, "Error getting user record for id %q", id)
	}
	au := idppb.WebauthnUser{}
	if err := proto.Unmarshal(ub, &au); err != nil {
		return nil, errors.Wrap(err, "Error unmarshaling user")
	}
	return &au, nil
}

// AddAuthenticatorToUser should associate the given user with the given
// authenticator
func (u *UserStore) AddAuthenticatorToUser(userID string, authenticator *idppb.WebauthnAuthenticator) error {
	*authenticator = *authenticator
	authenticator.UserId = userID
	ab, err := proto.Marshal(authenticator)
	if err != nil {
		return errors.Wrap(err, "Error marshaling authenticator")
	}
	if err := u.Storage.Put(authenticatorNS, string(authenticator.Id), ab); err != nil {
		return errors.Wrap(err, "Error storing authenticator")
	}
	return nil
}

// UserAuthenticators should return all the authenticators registered to the
// given user
func (u *UserStore) UserAuthenticators(userID string) ([]*idppb.WebauthnAuthenticator, error) {
	var auths []*idppb.WebauthnAuthenticator
	var innerErr error
	err := u.Storage.List(authenticatorNS, func(dat map[string][]byte) bool {
		for _, v := range dat {
			a := idppb.WebauthnAuthenticator{}
			if err := proto.Unmarshal(v, &a); err != nil {
				innerErr = err
				return false
			}
			if a.UserId == userID {
				auths = append(auths, &a)
			}
		}
		return true
	})
	if innerErr != nil {
		return nil, innerErr
	}
	if err != nil {
		return nil, errors.Wrap(err, "Error scanning authenticators")
	}
	return auths, nil
}

// GetAuthenticator returns the authenticator matching the provided ID
func (u *UserStore) GetAuthenticator(id []byte) (*idppb.WebauthnAuthenticator, error) {
	ab, err := u.Storage.Get(authenticatorNS, string(id))
	if err != nil {
		return nil, errors.Wrap(err, "Error getting authenticator")
	}
	a := idppb.WebauthnAuthenticator{}
	if err := proto.Unmarshal(ab, &a); err != nil {
		return nil, errors.Wrap(err, "Error unmarshaling authenticator")
	}
	return &a, nil
}

// Create a user + login
func (u *UserStore) CreateUser(userID, username, password string) error {
	wu := idppb.WebauthnUser{
		Id: userID,
	}
	ub, err := proto.Marshal(&wu)
	if err != nil {
		return errors.Wrap(err, "Error marshaling user")
	}
	if err := u.Storage.Put(userNS, userID, ub); err != nil {
		return errors.Wrap(err, "Error putting user")
	}
	pwb, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "Error hashing password")
	}
	su := storeUser{
		UserID:   userID,
		Password: pwb,
	}
	sub, err := json.Marshal(&su)
	if err != nil {
		return errors.Wrap(err, "Error marshaling login/user mapping")
	}
	if err := u.Storage.Put(userCredsNS, username, sub); err != nil {
		return errors.Wrap(err, "Error putting login/user mapping")
	}
	return nil
}
