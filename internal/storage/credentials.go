package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/webauthn"
	"lds.li/passidp/internal/config"
)

// CredentialStore is the on-disk passkey store.
//
// New enrollments are stored under Users as C2SP passkey records. Credentials
// is the legacy flat list and is left untouched.
type CredentialStore struct {
	Users       []*PasskeyUser `json:"users,omitzero"`
	Credentials []*Credential  `json:"credentials,omitzero"`
}

// PasskeyUser groups passkeys for one account.
type PasskeyUser struct {
	AccountID     uuid.UUID  `json:"accountId,omitzero"`
	PasskeyUserID string     `json:"passkeyUserId,omitzero"`
	HandleAliases [][]byte   `json:"handleAliases,omitzero"` // json/v2 encodes []byte as RFC 4648 §4 padded standard base64
	Passkeys      []*Passkey `json:"passkeys,omitzero"`
}

// Passkey is a C2SP passkey record plus UI metadata.
type Passkey struct {
	ID        uuid.UUID `json:"id,omitzero"`
	Record    string    `json:"record,omitzero"`
	Name      string    `json:"name,omitzero"`
	CreatedAt time.Time `json:"createdAt,omitzero"`
}

// Credential is a legacy go-webauthn credential.
type Credential struct {
	ID             uuid.UUID            `json:"id,omitzero"`
	CredentialID   []byte               `json:"credential_id,omitzero"`
	UserID         uuid.UUID            `json:"user_id,omitzero"`
	Name           string               `json:"name,omitzero"`
	CredentialData *webauthn.Credential `json:"credential_data,omitzero"`
	CreatedAt      time.Time            `json:"created_at,omitzero"`
}

// CredentialFile persists credentials to a JSON file. The file is created
// lazily on the first write that changes the store.
type CredentialFile struct {
	path string
	mu   sync.RWMutex
	data CredentialStore
	raw  []byte
}

var emptyStoreJSON = []byte("{}\n")

// NewCredentialFile opens an existing credential file or starts an empty
// in-memory store. The file is created on the first write.
func NewCredentialFile(path string) (*CredentialFile, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &CredentialFile{path: path, raw: emptyStoreJSON}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load credential store from %s: %w", path, err)
	}

	var data CredentialStore
	if err := jsonv2.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("load credential store from %s: %w", path, err)
	}
	return &CredentialFile{path: path, data: data, raw: raw}, nil
}

// ApplyConfig ensures a passkey user record exists for each config user and
// records historical WebAuthn handles as aliases.
func (c *CredentialFile) ApplyConfig(users config.Users) error {
	return c.Write(func(cs *CredentialStore) error {
		for _, user := range users {
			cs.EnsurePasskeyUser(user.ID, user.PasskeyHandleAliases())
		}
		return nil
	})
}

// Read calls fn with the current credential store contents.
func (c *CredentialFile) Read(fn func(data *CredentialStore)) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	fn(&c.data)
}

// Write calls fn with a copy of the credential store, then persists changes.
func (c *CredentialFile) Write(fn func(*CredentialStore) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var next CredentialStore
	if err := jsonv2.Unmarshal(c.raw, &next); err != nil {
		return fmt.Errorf("clone credential store: %w", err)
	}
	if err := fn(&next); err != nil {
		return err
	}
	b, err := marshalStore(&next)
	if err != nil {
		return fmt.Errorf("marshal credential store: %w", err)
	}
	if bytes.Equal(b, c.raw) {
		return nil
	}
	if err := writeFileAtomic(c.path, b); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}

	var stored CredentialStore
	if err := jsonv2.Unmarshal(b, &stored); err != nil {
		return fmt.Errorf("reload credential store: %w", err)
	}
	c.data = stored
	c.raw = b
	return nil
}

func marshalStore(cs *CredentialStore) ([]byte, error) {
	b, err := jsonv2.Marshal(cs, jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return b, nil
}

func writeFileAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("temp: %w", err)
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// EnsurePasskeyUser returns the passkey user for accountID, creating it with a
// new rand.Text() id if needed, and merges handle aliases.
func (cs *CredentialStore) EnsurePasskeyUser(accountID uuid.UUID, aliases [][]byte) *PasskeyUser {
	if pu := cs.passkeyUser(accountID); pu != nil {
		pu.addAliases(aliases)
		return pu
	}
	id := rand.Text()
	for cs.passkeyUserIDTaken(id) {
		id = rand.Text()
	}
	pu := &PasskeyUser{
		AccountID:     accountID,
		PasskeyUserID: id,
	}
	pu.addAliases(aliases)
	cs.Users = append(cs.Users, pu)
	return pu
}

func (cs *CredentialStore) passkeyUser(accountID uuid.UUID) *PasskeyUser {
	for _, user := range cs.Users {
		if user.AccountID == accountID {
			return user
		}
	}
	return nil
}

func (cs *CredentialStore) passkeyUserIDTaken(id string) bool {
	for _, user := range cs.Users {
		if user.PasskeyUserID == id {
			return true
		}
	}
	return false
}

// PasskeyUserID returns the canonical passkey user id for the account.
func (cs *CredentialStore) PasskeyUserID(accountID uuid.UUID) (string, bool) {
	if user := cs.passkeyUser(accountID); user != nil {
		return user.PasskeyUserID, true
	}
	return "", false
}

// LookupAccountByHandle finds an account by passkey user id or a stored alias.
func (cs *CredentialStore) LookupAccountByHandle(handle []byte) (uuid.UUID, bool) {
	for _, user := range cs.Users {
		if bytes.Equal([]byte(user.PasskeyUserID), handle) {
			return user.AccountID, true
		}
		if slices.ContainsFunc(user.HandleAliases, func(alias []byte) bool {
			return bytes.Equal(alias, handle)
		}) {
			return user.AccountID, true
		}
	}
	return uuid.Nil(), false
}

// RememberHandle records an observed authenticator user.id as an alias.
func (cs *CredentialStore) RememberHandle(accountID uuid.UUID, handle []byte, aliases [][]byte) {
	cs.EnsurePasskeyUser(accountID, aliases).addAliases([][]byte{handle})
}

// AddPasskey stores a new C2SP passkey under the account.
func (cs *CredentialStore) AddPasskey(accountID uuid.UUID, aliases [][]byte, passkey *Passkey) {
	user := cs.EnsurePasskeyUser(accountID, aliases)
	user.Passkeys = append(user.Passkeys, passkey)
}

// UserCredential is a listed passkey or legacy credential for an account.
type UserCredential struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
}

// UserCredentials returns the account's legacy credentials and C2SP passkeys.
func (cs *CredentialStore) UserCredentials(accountID uuid.UUID) []UserCredential {
	var out []UserCredential
	for _, cred := range cs.Credentials {
		if cred.UserID == accountID {
			out = append(out, UserCredential{ID: cred.ID, Name: cred.Name, CreatedAt: cred.CreatedAt})
		}
	}
	if user := cs.passkeyUser(accountID); user != nil {
		for _, passkey := range user.Passkeys {
			out = append(out, UserCredential{ID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt})
		}
	}
	return out
}

// DeleteUserCredential removes a legacy credential or C2SP passkey owned by
// the account. It returns false if no matching credential was found.
func (cs *CredentialStore) DeleteUserCredential(accountID, credentialID uuid.UUID) bool {
	for i, cred := range cs.Credentials {
		if cred.ID == credentialID && cred.UserID == accountID {
			cs.Credentials = append(cs.Credentials[:i], cs.Credentials[i+1:]...)
			return true
		}
	}
	if user := cs.passkeyUser(accountID); user != nil {
		for i, passkey := range user.Passkeys {
			if passkey.ID == credentialID {
				user.Passkeys = append(user.Passkeys[:i], user.Passkeys[i+1:]...)
				return true
			}
		}
	}
	return false
}

// WebAuthnCredentials returns go-webauthn credentials for login/registration,
// including legacy blobs and decoded C2SP records.
func (cs *CredentialStore) WebAuthnCredentials(accountID uuid.UUID) []webauthn.Credential {
	var creds []webauthn.Credential
	for _, cred := range cs.Credentials {
		if cred.UserID == accountID && cred.CredentialData != nil {
			creds = append(creds, *cred.CredentialData)
		}
	}
	if user := cs.passkeyUser(accountID); user != nil {
		for _, passkey := range user.Passkeys {
			cred, err := CredentialFromPasskeyRecord(passkey.Record)
			if err != nil {
				continue
			}
			creds = append(creds, *cred)
		}
	}
	return creds
}

func (pu *PasskeyUser) addAliases(handles [][]byte) {
	for _, handle := range handles {
		if len(handle) == 0 || bytes.Equal(handle, []byte(pu.PasskeyUserID)) {
			continue
		}
		if slices.ContainsFunc(pu.HandleAliases, func(alias []byte) bool {
			return bytes.Equal(alias, handle)
		}) {
			continue
		}
		pu.HandleAliases = append(pu.HandleAliases, bytes.Clone(handle))
	}
}
