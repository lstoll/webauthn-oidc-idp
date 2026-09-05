package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenTest(t *testing.T) {
	sqlDB := OpenTest(t)

	var count int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).Scan(&count); err != nil {
		t.Fatalf("query tables: %v", err)
	}
	if count == 0 {
		t.Fatal("expected migrated tables")
	}
}

func TestSanitizeTestDBName(t *testing.T) {
	if got := sanitizeTestDBName("TestFoo/Bar#baz"); got != "TestFoo_Bar_baz" {
		t.Fatalf("sanitizeTestDBName() = %q, want TestFoo_Bar_baz", got)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsNewerSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 'now')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "database schema version 99 is newer than this binary") {
		t.Fatalf("Open() error = %v", err)
	}
}
