package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sync"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
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
	HandleAliases []string   `json:"handleAliases,omitzero"` // standard padded base64, same as encoding/json/v2 format:base64
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

// CredentialFile persists credentials to a JSON file and reloads when the
// file changes on disk, so external tools can update credentials while the
// server is running. The file is created lazily on the first write.
type CredentialFile struct {
	path string
	mu   sync.Mutex
	file *jsonfile.JSONFile[CredentialStore]
	mod  time.Time
}

// NewCredentialFile opens an existing credential file or starts an empty
// in-memory store. The file is created on the first write.
func NewCredentialFile(path string) (*CredentialFile, error) {
	file, err := openCredentialFile(path)
	if err != nil {
		return nil, err
	}

	cf := &CredentialFile{path: path, file: file}
	if info, err := os.Stat(path); err == nil {
		cf.mod = info.ModTime()
	}
	return cf, nil
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reloadIfChanged()
	c.file.Read(fn)
}

// Write calls fn with a copy of the credential store, then persists changes.
func (c *CredentialFile) Write(fn func(*CredentialStore) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reloadIfChanged()
	if err := c.file.Write(fn); err != nil {
		return err
	}
	c.refreshModTime()
	return nil
}

func (c *CredentialFile) reloadIfChanged() {
	info, err := os.Stat(c.path)
	if err != nil {
		return
	}
	if !info.ModTime().After(c.mod) {
		return
	}
	file, err := jsonfile.Load[CredentialStore](c.path)
	if err != nil {
		return
	}
	c.file = file
	c.mod = info.ModTime()
}

func (c *CredentialFile) refreshModTime() {
	info, err := os.Stat(c.path)
	if err != nil {
		return
	}
	c.mod = info.ModTime()
}

func openCredentialFile(path string) (*jsonfile.JSONFile[CredentialStore], error) {
	file, err := jsonfile.Load[CredentialStore](path)
	if errors.Is(err, fs.ErrNotExist) {
		file, err = jsonfile.New[CredentialStore](path)
		if err != nil {
			return nil, fmt.Errorf("create credential store: %w", err)
		}
		return file, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load credential store from %s: %w", path, err)
	}
	return file, nil
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
	encoded := base64.StdEncoding.EncodeToString(handle)
	for _, user := range cs.Users {
		if bytes.Equal([]byte(user.PasskeyUserID), handle) {
			return user.AccountID, true
		}
		if slices.Contains(user.HandleAliases, encoded) {
			return user.AccountID, true
		}
	}
	return uuid.Nil, false
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
		alias := base64.StdEncoding.EncodeToString(handle)
		if slices.Contains(pu.HandleAliases, alias) {
			continue
		}
		pu.HandleAliases = append(pu.HandleAliases, alias)
	}
}
