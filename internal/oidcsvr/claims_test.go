package oidcsvr

import (
	"testing"
	"uuid"

	"lds.li/passidp/internal/config"
)

func TestIDTokenClaimsFromMap(t *testing.T) {
	got := idTokenClaimsFromMap(map[string]any{
		"sub":            "user-1",
		"email":          "a@example.com",
		"email_verified": true,
		"groups":         []string{"eng"},
		"custom":         "value",
		"cleared":        nil,
	})

	if got.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", got.Subject)
	}
	if got.Additional["email"] != "a@example.com" {
		t.Errorf("email = %v, want a@example.com", got.Additional["email"])
	}
	if _, ok := got.Additional["sub"]; ok {
		t.Errorf("sub should not be in Additional")
	}
	if _, ok := got.Additional["cleared"]; ok {
		t.Errorf("nil claims should be omitted")
	}
	if got.Additional["custom"] != "value" {
		t.Errorf("custom = %v, want value", got.Additional["custom"])
	}
}

func TestDefaultIDTokenClaims(t *testing.T) {
	user := &config.User{
		ID:                uuid.New(),
		Email:             "a@example.com",
		FullName:          "A User",
		Groups:            []string{"eng"},
		PreferredUsername: "auser",
	}

	got := defaultIDTokenClaims(user)
	if got["email"] != user.Email {
		t.Errorf("email = %v, want %s", got["email"], user.Email)
	}
	if _, ok := got["sub"]; ok {
		t.Errorf("default claims should not set sub")
	}
	if got["preferred_username"] != "auser" {
		t.Errorf("preferred_username = %v, want auser", got["preferred_username"])
	}

	empty := defaultIDTokenClaims(&config.User{Email: "b@example.com"})
	if _, ok := empty["groups"]; ok {
		t.Errorf("empty groups should be omitted")
	}
	if _, ok := empty["preferred_username"]; ok {
		t.Errorf("empty preferred_username should be omitted")
	}
}
