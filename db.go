package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lstoll/oidc/core"
)

// schemaVersion is the current version of the database schema. It may be used
// to handle schema changes in the future.
const schemaVersion uint = 1

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrUserNotActivated    = errors.New("user not activated")
	ErrUserEmailTaken      = errors.New("user email taken")
	ErrUnauthenticatedUser = errors.New("unauthenticated user")
	ErrCredentialNotFound  = errors.New("credential not found")
)

// schema is the database schema, serializable in JSON.
type schema struct {
	// Version is the schemaVersion of the on-disk database.
	Version uint `json:"version"`

	// Users stores all users in the system, along with their WebAuthn credentials.
	// The key is the user's ID.
	Users map[string]User `json:"users"`

	// OIDCSession is a map of session ID to core.Session serialized in JSON.
	OIDCSessions map[string]json.RawMessage `json:"oidcSessions"`

	// AuthenticatedUsers tracks authenticated users.
	// The key is the session ID from OIDCSessions.
	AuthenticatedUsers map[string]AuthenticatedUser `json:"authenticatedUsers"`

	// OIDCKeyset is the keyset for signing OIDC messages.
	OIDCKeyset OIDCKeyset `json:"oidcKeyset"`
}

// OIDCKeyset represents the OIDC signing keys as stored in the DB
type OIDCKeyset struct {
	// LastRotated is the time the last rotation was performed on the set
	LastRotated time.Time `json:"lastRotated,omitempty"`
	// UpcomingKeyID is the keyset key ID for the newly-provisioned key, that is
	// waiting to get rotated in to being active.
	UpcomingKeyID uint32 `json:"upcomingKeyID"`
	// Keyset is the JSON formatted representation of the tink keyset.
	Keyset json.RawMessage `json:"keyset,omitempty"`
}

// User implements webauthn.User.
type User struct {
	// ID uniquely identifies the user, and is assigned automatically.
	// This is stable for the lifetime of the user.
	ID string `json:"id"`

	// Email address for the user. This is changeable, however it must be unique as
	// it's the "exposed" ID for a user for login purposes.
	Email string `json:"email"`

	// FullName to refer to the user as.
	FullName string `json:"fullName"`

	// Activated if the user is valid to be used.
	Activated bool `json:"activated"`

	// EnrollmentKey used for enrolling users first token.
	EnrollmentKey string `json:"enrollmentKey"`

	// Credentials is the user's WebAuthn credentials keyed by a user-provided identifier.
	Credentials map[string]webauthn.Credential `json:"credentials"`
}

func (u User) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u User) WebAuthnName() string {
	return u.Email
}

func (u User) WebAuthnDisplayName() string {
	return u.FullName
}

func (u User) WebAuthnIcon() string {
	return ""
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	var ret []webauthn.Credential
	for _, v := range u.Credentials {
		ret = append(ret, v)
	}
	return ret
}

// AuthenticatedUser are the details flagged for an authenticated user of the
// system.
type AuthenticatedUser struct {
	// Subject (required) is the unique identifier for the authenticated user.
	// This should be stable over time.
	Subject string `json:"subject"`
	// Email (optional), for when the email/profile scope is requested
	Email string `json:"email,omitempty"`
	// FullName (optional), for when the profile scope is requested
	FullName string `json:"fullName,omitempty"`
	// Groups (optional), for when the groups scope is requested
	Groups []string `json:"groups,omitempty"`
	// ExtraClaims (optional) fields to add to the returned ID token claims
	ExtraClaims map[string]interface{} `json:"extraClaims,omitempty"`
	// PolicyContext is internal data, that is passed to the policies that are
	// evaluated downstream. This data is not presented to the user.
	PolicyContext map[string]interface{} `json:"policyContext,omitempty"`
}

// openDB opens the database at path, creating the file if it does not exist.
func openDB(path string) (*DB, error) {
	f, err := jsonfile.Load[schema](path)
	if errors.Is(err, fs.ErrNotExist) {
		f, err = jsonfile.New[schema](path)
		if err != nil {
			return nil, err
		}
		err = f.Write(func(db *schema) error {
			db.Version = schemaVersion
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	var ver uint
	f.Read(func(db *schema) { ver = db.Version })
	if ver != schemaVersion {
		return nil, fmt.Errorf("unsupported database version: %d", ver)
	}
	return &DB{f: f}, nil
}

// DB is the IDP database.
// The database consists of a single JSON file stored on disk.
// It contains unencrypted private key material.
type DB struct {
	f *jsonfile.JSONFile[schema]
}

func (db *DB) Reload() error {
	return db.f.Reload(func(db *schema) error {
		if db.Version != schemaVersion {
			return fmt.Errorf("unsupported database version: %d", db.Version)
		}
		return nil
	})
}

func (db *DB) GetUserByID(userID string) (User, error) {
	var (
		v  User
		ok bool
	)
	db.f.Read(func(db *schema) {
		v, ok = db.Users[userID]
	})
	if !ok {
		return v, ErrUserNotFound
	}
	return v, nil
}

func (db *DB) GetActivatedUserByID(id string) (User, error) {
	user, err := db.GetUserByID(id)
	if err != nil {
		return User{}, err
	}
	if !user.Activated {
		return User{}, ErrUserNotActivated
	}
	return user, nil
}

func (db *DB) CreateUser(user User) (User, error) {
	if user.ID != "" {
		return User{}, fmt.Errorf("user ID already assigned")
	}
	if user.EnrollmentKey != "" {
		return User{}, fmt.Errorf("user enrollment key already assigned")
	}
	user.ID = uuid.NewString()
	user.EnrollmentKey = uuid.NewString()
	user.Credentials = make(map[string]webauthn.Credential)
	err := db.f.Write(func(db *schema) error {
		if _, ok := db.Users[user.ID]; ok {
			panic("generated UUID already in use")
		}
		var dupe bool
		for _, u := range db.Users {
			if u.Email == user.Email {
				dupe = true
				break
			}
		}
		if dupe {
			return ErrUserEmailTaken
		}
		if len(db.Users) == 0 {
			db.Users = make(map[string]User)
		}
		db.Users[user.ID] = user
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (db *DB) UpdateUser(user User) error {
	if user.ID == "" {
		return errors.New("user ID missing")
	}
	err := db.f.Write(func(db *schema) error {
		if _, ok := db.Users[user.ID]; !ok {
			return ErrUserNotFound
		}
		for _, u := range db.Users {
			if u.ID != user.ID && u.Email == user.Email {
				return ErrUserEmailTaken
			}
		}
		db.Users[user.ID] = user
		return nil
	})
	return err
}

func (db *DB) UpdateUserCredential(userID string, cred webauthn.Credential) error {
	err := db.f.Write(func(db *schema) error {
		user, ok := db.Users[userID]
		if !ok {
			return ErrUserNotFound
		}
		for k, v := range user.Credentials {
			if bytes.Equal(cred.ID, v.ID) {
				db.Users[userID].Credentials[k] = cred
				return nil
			}
		}
		return ErrCredentialNotFound
	})
	return err
}

func (db *DB) CreateUserCredential(userID, name string, cred webauthn.Credential) error {
	err := db.f.Write(func(db *schema) error {
		if _, ok := db.Users[userID]; !ok {
			return ErrUserNotFound
		}
		db.Users[userID].Credentials[name] = cred
		return nil
	})
	return err
}

func (db *DB) DeleteUserCredential(userID string, name string) error {
	err := db.f.Write(func(db *schema) error {
		if _, ok := db.Users[userID]; !ok {
			return ErrUserNotFound
		}
		delete(db.Users[userID].Credentials, name)
		return nil
	})
	return err
}

func (db *DB) ListUsers() []User {
	var users []User
	db.f.Read(func(db *schema) {
		for _, v := range db.Users {
			users = append(users, v)
		}
	})
	return users
}

func (db *DB) Authenticate(sessionID string, auth AuthenticatedUser) error {
	return db.f.Write(func(db *schema) error {
		if len(db.AuthenticatedUsers) == 0 {
			db.AuthenticatedUsers = make(map[string]AuthenticatedUser)
		}
		db.AuthenticatedUsers[sessionID] = auth
		return nil
	})
}

func (db *DB) GetAuthenticatedUser(sessionID string) (AuthenticatedUser, error) {
	var (
		v  AuthenticatedUser
		ok bool
	)
	db.f.Read(func(db *schema) {
		v, ok = db.AuthenticatedUsers[sessionID]
	})
	if !ok {
		return AuthenticatedUser{}, ErrUnauthenticatedUser
	}
	return v, nil
}

func (db *DB) SessionManager() core.SessionManager {
	return &sessionManager{f: db.f}
}

func (db *DB) GetOIDCKeyset() OIDCKeyset {
	var ks OIDCKeyset
	db.f.Read(func(data *schema) {
		ks = data.OIDCKeyset
	})
	return ks
}

func (db *DB) PutOIDCKeyset(ks OIDCKeyset) error {
	return db.f.Write(func(db *schema) error {
		db.OIDCKeyset = ks
		return nil
	})
}

func migrateSQLToJSON(sqldb *storage, jsondb *DB) error {
	ctx := context.Background()
	users, err := sqldb.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("sql.ListUsers: %w", err)
	}
	for _, u := range users {
		user, ok, err := sqldb.GetUserByID(ctx, u.ID, true)
		if err != nil {
			return fmt.Errorf("sql.GetUserByID: %w", err)
		}
		if !ok {
			return fmt.Errorf("sql.GetUserByID: user %s not found", u.ID)
		}
		newUser := User{
			ID:            user.ID,
			Email:         user.Email,
			FullName:      user.FullName,
			Activated:     user.Activated,
			EnrollmentKey: user.EnrollmentKey,
			Credentials:   make(map[string]webauthn.Credential),
		}
		for _, cred := range user.Credentials {
			newUser.Credentials[cred.Name] = cred.Credential
		}
		if err := jsondb.createMigratedUser(newUser); err != nil {
			return fmt.Errorf("json.createMigratedUser: %w", err)
		}
	}
	return nil
}

// createMigratedUser saves the given user as is in the database.
// Do not use; it's temporary and will be deleted in the near future.
func (db *DB) createMigratedUser(user User) error {
	return db.f.Write(func(db *schema) error {
		if len(db.Users) == 0 {
			db.Users = make(map[string]User)
		}
		db.Users[user.ID] = user
		return nil
	})
}
