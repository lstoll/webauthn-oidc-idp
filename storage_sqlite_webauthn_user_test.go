package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebauthnUserStorage(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	u := &WebauthnUser{
		Email: "abc@def.com",
	}
	id, err := s.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("putting user: %v", err)
	}
	u.ID = id

	_, ok, err := s.GetUserByID(ctx, u.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("inactive user should not be returned")
	}

	randb := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randb); err != nil {
		t.Fatal(err)
	}

	err = s.AddCredentialToUser(ctx, u.ID, webauthn.Credential{ID: randb}, "test name")
	if err != nil {
		t.Fatal(err)
	}

	u, ok, err = s.GetUserByID(ctx, u.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no user got")
	}

	if len(u.Credentials) != 1 {
		t.Errorf("user should have %d credentials, got %d", 1, len(u.Credentials))
	}

	us, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 {
		t.Errorf("want 1 user, got %d", len(us))
	}
}

func newTestStorage(t *testing.T) *storage {
	t.Helper()

	s, err := newStorage(context.Background(), fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", filepath.Join(t.TempDir(), "t.db")))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
