package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	_ "github.com/mattn/go-sqlite3"
)

func TestMigrateData(t *testing.T) {
	uuidUserID := uuid.MustParse(`237bd488-059f-4ce7-b5ea-62bc72f92fee`)

	workdir := t.TempDir()
	src, err := os.ReadFile("testdata/db.json")
	if err != nil {
		t.Fatalf("failed to read source file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "db.json"), src, 0644); err != nil {
		t.Fatalf("failed to write destination file: %v", err)
	}

	filedb, err := openDB(filepath.Join(workdir, "db.json"))
	if err != nil {
		t.Fatalf("failed to open file db: %v", err)
	}

	sqldb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	defer sqldb.Close()

	if err := db.Migrate(t.Context(), sqldb); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	if err := migrateData(t.Context(), filedb, sqldb); err != nil {
		t.Fatalf("failed to migrate data: %v", err)
	}

	filedb.f.Read(func(data *schema) {
		if !data.UsersMigrated {
			t.Fatalf("users not marked as migrated")
		}
	})

	q := queries.New(sqldb)

	users, err := q.GetUsers(t.Context())
	if err != nil {
		t.Fatalf("failed to get users: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	for _, user := range users {
		if user.ID == uuidUserID {
			creds, err := q.GetUserCredentials(t.Context(), user.ID)
			if err != nil {
				t.Fatalf("failed to get user credentials: %v", err)
			}
			if len(creds) != 2 {
				t.Fatalf("expected 2 credentials, got %d", len(creds))
			}
		} else {
			if user.OverrideSubject.String != "non-uuid" {
				t.Fatalf("expected override subject to be non-uuid, got %s", user.OverrideSubject.String)
			}
		}
	}
}
