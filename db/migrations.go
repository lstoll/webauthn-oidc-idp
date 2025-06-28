package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
)

//go:embed migrations/*.sql
var migrationScripts embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	type migration struct {
		Idx    int64
		Script string
	}

	var migrations []migration

	entries, err := fs.ReadDir(migrationScripts, "migrations")
	if err != nil {
		return fmt.Errorf("reading migrations directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Extract the timestamp prefix from the filename
		// Format: YYYY-MM-DD-HHMM_name.sql
		name := entry.Name()
		if len(name) < 15 { // Minimum length for timestamp prefix
			return fmt.Errorf("migration script %s has less than 15 characters", name)
		}

		// Convert timestamp to integer for sorting
		// Format: YYYYMMDDHHMM
		idx, err := strconv.ParseInt(name[:4]+name[5:7]+name[8:10]+name[11:15], 10, 64)
		if err != nil {
			return fmt.Errorf("migration script %s has invalid timestamp: %v", name, err)
		}

		script, err := fs.ReadFile(migrationScripts, "migrations/"+name)
		if err != nil {
			return fmt.Errorf("reading migration script: %v", err)
		}

		migrations = append(migrations, migration{
			Idx:    idx,
			Script: string(script),
		})
	}

	// Sort migrations by their timestamp index
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Idx < migrations[j].Idx
	})

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`create table if not exists migrations (
		idx integer primary key not null,
		at datetime not null
		);`,
	); err != nil {
		return fmt.Errorf("creating migrations table: %v", err)
	}

	for _, mig := range migrations {
		var idx int64
		err := tx.QueryRowContext(ctx, `select idx from migrations where idx = $1;`, mig.Idx).Scan(&idx)
		if err == nil {
			// selected fine so we've already inserted migration, next
			// please.
			continue
		}
		if err != sql.ErrNoRows {
			// genuine error
			return fmt.Errorf("checking for migration existence: %v", err)
		}

		if _, err := tx.ExecContext(ctx, mig.Script); err != nil {
			return fmt.Errorf("running migration: %v", err)
		}

		if _, err := tx.ExecContext(ctx, `insert into migrations (idx, at) values ($1, datetime('now'));`, mig.Idx); err != nil {
			return fmt.Errorf("inserting migration: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %v", err)
	}

	return nil
}
