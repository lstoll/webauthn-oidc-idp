package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestOpenDB(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := openDB(filepath.Join(dir, "t1.json"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}

	err = os.WriteFile(filepath.Join(dir, "t2.json"), []byte(`{"version": 2}`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err = openDB(filepath.Join(dir, "t2.json"))
	if err == nil {
		t.Error("OpenDB: want error due to unsupported version, got none")
	}
}

func TestReloadDB(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "db.json")

	db, err := openDB(file)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}

	if want, got := 0, len(db.ListUsers()); got != want {
		t.Fatalf("want %d users, got: %d", want, got)
	}

	err = os.WriteFile(file, []byte(`{"version": 1, "users": {"uuid": {"id": "uuid"}}}`), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := db.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if want, got := 1, len(db.ListUsers()); got != want {
		t.Fatalf("want %d users after reload, got: %d", want, got)
	}
}

func TestUsers(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)

	user := User{Email: "abc@def.com"}
	newUser, err := db.CreateUser(user)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := db.CreateUser(newUser); err == nil {
		t.Fatal("CreateUser did not reject user with existing ID")
	}

	if _, err := db.CreateUser(User{Email: user.Email}); err != ErrUserEmailTaken {
		t.Fatalf("CreateUser did not reject non-unique email, got: %v", err)
	}

	if _, err := db.GetUserByID("foo"); err != ErrUserNotFound {
		t.Fatalf("want GetUserByID to return user not found error, got: %v", err)
	}

	user2, err := db.CreateUser(User{Email: "me@example.com"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpdateUser(User{ID: user2.ID, Email: user.Email}); err != ErrUserEmailTaken {
		t.Fatalf("UpdateUser did not reject non-unique email, got: %v", err)
	}
	err = db.CreateUserCredential(user2.ID, "1pass", WebauthnCredential{Credential: webauthn.Credential{ID: []byte("ID")}})
	if err != nil {
		t.Fatalf("AddCredentialToUser: %v", err)
	}

	if err := db.UpdateUser(User{}); err == nil {
		t.Fatal("UpdateUser: want missing user ID error")
	}

	err = db.CreateUserCredential(newUser.ID, "test", WebauthnCredential{Credential: webauthn.Credential{ID: []byte("ID")}})
	if err != nil {
		t.Fatalf("AddCredentialToUser: %v", err)
	}

	user, err = db.GetUserByID(newUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if len(user.Credentials) != 1 {
		t.Errorf("want user to have 1 credentials, got %d", len(user.Credentials))
	}

	if err := db.UpdateUserCredential(user.ID, user.Credentials["test"].Credential); err != nil {
		t.Fatalf("UpdateUserCredential: %v", err)
	}
	if err := db.UpdateUserCredential(user.ID, webauthn.Credential{}); err != ErrCredentialNotFound {
		t.Fatalf("UpdateUserCredential: want credential not found error, got: %v", err)
	}
	if err := db.UpdateUserCredential("404", webauthn.Credential{}); err != ErrUserNotFound {
		t.Fatalf("UpdateUserCredential: want user not found error, got: %v", err)
	}

	if err := db.DeleteUserCredential(user.ID, "test"); err != nil {
		t.Fatalf("DeleteUserCredential: %v", err)
	}
	if err := db.DeleteUserCredential("404", "test"); err != ErrUserNotFound {
		t.Fatalf("DeleteUserCredential: want user not found error, got: %v", err)
	}

	users := db.ListUsers()
	if len(users) != 2 {
		t.Errorf("ListUsers: want 1 user, got %d", len(users))
	}
	idx := slices.IndexFunc[[]User](users, func(u User) bool {
		return u.ID == user.ID
	})
	if got := len(users[idx].Credentials); got != 0 {
		t.Errorf("want user to have no credentials left, got: %d", got)
	}
}

func TestAuthenticatedUsers(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)

	if _, err := db.GetAuthenticatedUser("session"); err != ErrUnauthenticatedUser {
		t.Fatalf("GetAuthenticated: want unauthenticated user error, got: %v", err)
	}

	if err := db.Authenticate("session", AuthenticatedUser{Subject: "me@example.com"}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	auth, err := db.GetAuthenticatedUser("session")
	if err != nil {
		t.Fatalf("GetAuthenticated: %v", err)
	}
	if auth.Subject != "me@example.com" {
		t.Fatalf("GetAuthenticated: got unexpected subject: %s", auth.Subject)
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()

	db, err := openDB(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	return db
}
