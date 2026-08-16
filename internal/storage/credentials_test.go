package storage_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"uuid"

	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

func TestNewCredentialFileLazyCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no file before first write, stat err=%v", err)
	}

	if err := store.Write(func(*storage.CredentialStore) error {
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no file after no-op write, stat err=%v", err)
	}

	if err := store.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{Name: "test"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file after write: %v", err)
	}
}

func TestCredentialFilePrettyPrinted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{Name: "test"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("\n  ")) {
		t.Fatalf("expected indented JSON, got:\n%s", raw)
	}
	if raw[len(raw)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}
}

func TestCredentialFileWriteRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{Name: "nope"})
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected write error")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no file after failed write, stat err=%v", err)
	}

	var count int
	store.Read(func(cs *storage.CredentialStore) {
		count = len(cs.Credentials)
	})
	if count != 0 {
		t.Fatalf("expected empty store after failed write, got %d credentials", count)
	}
}

func TestNewCredentialFileOpensExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	created, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{Name: "existing"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	opened, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	opened.Read(func(cs *storage.CredentialStore) {
		count = len(cs.Credentials)
	})
	if count != 1 {
		t.Fatalf("expected 1 credential, got %d", count)
	}
}

func TestApplyConfigLeavesLegacyCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}

	accountID := uuid.MustParse("4854735c-5a01-4a2d-b7a0-330a5b5928a9")
	handle := uuid.MustParse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	legacyID := uuid.New()
	if err := store.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:     legacyID,
			UserID: accountID,
			Name:   "old-key",
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	users := config.Users{{
		ID:             accountID,
		WebauthnHandle: handle,
		Metadata:       map[string]any{"overrideSubject": "custom-subject"},
	}}
	if err := store.ApplyConfig(users); err != nil {
		t.Fatal(err)
	}

	var passkeyUserID string
	store.Read(func(cs *storage.CredentialStore) {
		if len(cs.Credentials) != 1 || cs.Credentials[0].ID != legacyID || cs.Credentials[0].Name != "old-key" {
			t.Fatalf("legacy credentials mutated: %+v", cs.Credentials)
		}
		if len(cs.Users) != 1 {
			t.Fatalf("expected 1 passkey user, got %d", len(cs.Users))
		}
		pu := cs.Users[0]
		if pu.PasskeyUserID == "" {
			t.Fatal("missing passkey user id")
		}
		if len(pu.Passkeys) != 0 {
			t.Fatalf("should not convert legacy credentials to passkeys, got %d", len(pu.Passkeys))
		}
		passkeyUserID = pu.PasskeyUserID

		mustLookup := func(handle []byte) {
			t.Helper()
			got, ok := cs.LookupAccountByHandle(handle)
			if !ok || got != accountID {
				t.Fatalf("lookup %q: got %s ok=%v", handle, got, ok)
			}
		}
		mustLookup([]byte(pu.PasskeyUserID))
		mustLookup(handle[:])
		mustLookup([]byte(accountID.String()))
		mustLookup([]byte("custom-subject"))

		if !slices.ContainsFunc(pu.HandleAliases, func(alias []byte) bool {
			return bytes.Equal(alias, handle[:])
		}) {
			t.Fatalf("handle aliases = %q, want raw handle %q", pu.HandleAliases, handle[:])
		}
	})

	if err := store.ApplyConfig(users); err != nil {
		t.Fatal(err)
	}
	store.Read(func(cs *storage.CredentialStore) {
		if cs.Users[0].PasskeyUserID != passkeyUserID {
			t.Fatalf("passkey user id changed on re-apply: %q -> %q", passkeyUserID, cs.Users[0].PasskeyUserID)
		}
		if len(cs.Credentials) != 1 {
			t.Fatalf("legacy credentials mutated on re-apply")
		}
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Credentials json.RawMessage `json:"credentials"`
		Users       []struct {
			HandleAliases []string `json:"handleAliases"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Credentials) == 0 || string(file.Credentials) == "null" {
		t.Fatalf("credentials key missing from file: %s", raw)
	}
	if len(file.Users) == 0 {
		t.Fatalf("users key missing from file: %s", raw)
	}
	padded := base64.StdEncoding.EncodeToString(handle[:])
	if !slices.Contains(file.Users[0].HandleAliases, padded) {
		t.Fatalf("on-disk handleAliases = %q, want padded std base64 %q", file.Users[0].HandleAliases, padded)
	}
}
