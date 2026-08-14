package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// CredentialStore represents the on-disk store for webauthn credentials.
type CredentialStore struct {
	Credentials []*Credential `json:"credentials,omitzero"`
}

// Credential is an individual webauthn credential stored in the database.
type Credential struct {
	// ID is a unique identifier for this credential.
	ID uuid.UUID `json:"id,omitzero"`
	// CredentialID is the ID for the credential, opaque bytes from go-webauthn
	// credential data.
	CredentialID []byte `json:"credential_id,omitzero"`
	// UserID is the ID of the user this credential is associated with.
	UserID uuid.UUID `json:"user_id,omitzero"`
	// Name is the name of the credential.
	Name string `json:"name,omitzero"`
	// CredentialData is the credential data from go-webauthn
	CredentialData *webauthn.Credential `json:"credential_data,omitzero"`
	// CreatedAt is the time the credential was created.
	CreatedAt time.Time `json:"created_at,omitzero"`
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
