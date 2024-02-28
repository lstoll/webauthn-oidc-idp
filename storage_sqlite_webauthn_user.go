package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

func init() {
	gob.Register(webauthn.Credential{})
}

func (s *storage) GetUserByID(ctx context.Context, id string, allowInactive bool) (*WebauthnUser, bool, error) {
	if allowInactive {
		return s.getUserByQuery(ctx, `select id, email, full_name, activated, enrollment_key from users where id=$1`, id)
	}
	return s.getUserByQuery(ctx, `select id, email, full_name, activated, enrollment_key from users where id=$1 and activated=1`, id)
}

func (s *storage) getUserByQuery(ctx context.Context, query string, args ...interface{}) (*WebauthnUser, bool, error) {
	u := WebauthnUser{}
	if err := s.db.QueryRowContext(ctx, query, args...).
		Scan(&u.ID, &u.Email, &u.FullName, &u.Activated, &u.EnrollmentKey); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("getting user: %w", err)
	}
	rows, err := s.db.Query(`select id, name, credential from webauthn_credentials where user_id=$1`, u.ID)
	if err != nil {
		return nil, false, fmt.Errorf("selecting credentials for user %s: %w", u.ID, err)
	}
	for rows.Next() {
		var (
			ucred WebauthnUserCredential
			cb    []byte
		)
		if err := rows.Scan(&ucred.ID, &ucred.Name, &cb); err != nil {
			return nil, false, fmt.Errorf("scanning credential: %w", err)
		}
		var cred webauthn.Credential
		if err := gob.NewDecoder(bytes.NewReader(cb)).Decode(&cred); err != nil {
			return nil, false, fmt.Errorf("ungob credential: %w", err)
		}
		ucred.Credential = cred
		u.Credentials = append(u.Credentials, ucred)
	}
	if err := rows.Close(); err != nil {
		return nil, false, fmt.Errorf("closing rows: %w", err)
	}
	return &u, true, nil
}

func (s *storage) CreateUser(ctx context.Context, u *WebauthnUser) (id string, err error) {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if _, err := s.db.ExecContext(ctx, `insert into users (id, email, full_name, activated, enrollment_key) values ($1, $2, $3, $4, $5)`, u.ID, u.Email, u.FullName, u.Activated, u.EnrollmentKey); err != nil {
		return "", fmt.Errorf("inserting user %s: %w", u.ID, err)
	}
	return u.ID, nil
}

func (s *storage) AddCredentialToUser(ctx context.Context, userid string, credential webauthn.Credential, keyName string) error {
	cid := base64.RawStdEncoding.EncodeToString(credential.ID)
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(credential); err != nil {
		return fmt.Errorf("encoding credential: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `insert into webauthn_credentials (id, user_id, name, credential) values ($1, $2, $3, $4)`, cid, userid, keyName, buf.Bytes()); err != nil {
		return fmt.Errorf("inserting credential: %w", err)
	}
	return nil
}

func (s *storage) ListUsers(_ context.Context) ([]*WebauthnUser, error) {
	// TODO - do we ever need credentials here? Skipping for convenience
	var ret []*WebauthnUser
	rows, err := s.db.Query(`select id, email, full_name from users`)
	if err != nil {
		return nil, fmt.Errorf("selecting users: %w", err)
	}
	for rows.Next() {
		var u WebauthnUser
		if err := rows.Scan(&u.ID, &u.Email, &u.FullName); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		ret = append(ret, &u)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing rows: %w", err)
	}
	return ret, nil
}

type WebauthnUser struct {
	// ID uniquely identifies the user, and is assigned by the storage
	// implementation. This is stable for the life of the user
	ID string
	// Email address for the user. This is changeable, however must be unique as
	// it's the "exposed" ID for a user for login purposes
	Email string
	// FullName to refer to the user as
	FullName string
	// Activated if the user is valid to be used
	Activated bool
	// EnrollmentKey used for enrolling users first token
	EnrollmentKey string
	// Credentials for webauthn authenticators
	Credentials []WebauthnUserCredential
}

type WebauthnUserCredential struct {
	// ID is the URL encoded base64 of the credentials ID, for easier passing
	// around
	ID string
	// Name is a friendly name the user can refer to this credential with
	Name string
	// Credential is the actual credential
	Credential webauthn.Credential
}
