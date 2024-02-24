package main

import (
	"context"
	"crypto/rand"
	"io"
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

	u.Activated = true

	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	randb := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randb); err != nil {
		t.Fatal(err)
	}

	cid, err := s.AddCredentialToUser(ctx, u.ID, webauthn.Credential{}, "test name")
	if err != nil {
		t.Fatal(err)
	}

	u, ok, err = s.GetUserByID(ctx, u.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no user got")
	}

	if len(u.Credentials) != 1 {
		t.Errorf("user should have %d credentials, got %d", 1, len(u.Credentials))
	}

	if err := s.UpdateCredential(ctx, u.ID, u.Credentials[0].Credential); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteCredentialFromuser(ctx, u.ID, cid); err != nil {
		t.Fatal(err)
	}

	us, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 {
		t.Errorf("want 1 user, got %d", len(us))
	}
}
