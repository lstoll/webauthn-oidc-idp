package storage_test

import (
	"os"
	"path/filepath"
	"testing"

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

func TestCredentialFileReloadsExternalChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}

	other, err := storage.NewCredentialFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{Name: "external"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var count int
	store.Read(func(cs *storage.CredentialStore) {
		count = len(cs.Credentials)
	})
	if count != 1 {
		t.Fatalf("expected reloaded credential count 1, got %d", count)
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
