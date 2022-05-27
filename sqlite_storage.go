package main

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type storage struct {
	db  *sql.DB
	log logrus.FieldLogger
}

func newStorage(ctx context.Context, logger logrus.FieldLogger, connStr string) (*storage, error) {
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, fmt.Errorf("opening DB: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %v", err)
	}

	s := &storage{
		db:  db,
		log: logger,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *storage) execTx(ctx context.Context, f func(ctx context.Context, tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := f(ctx, tx); err != nil {
		// Not much we can do about an error here, but at least the database will
		// eventually cancel it on its own if it fails
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *storage) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(
		ctx,
		`create table if not exists migrations (
		idx integer primary key not null,
		at datetime not null
		);`,
	); err != nil {
		return err
	}

	if err := s.execTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		for _, mig := range migrations {
			var idx int64
			err := tx.QueryRowContext(ctx, `select idx from migrations where idx = $1;`, mig.Idx).Scan(&idx)
			if err == nil {
				// selected fine so we've already inserted migration, next
				// please.
				continue
			}
			if err != nil && err != sql.ErrNoRows {
				// genuine error
				return fmt.Errorf("checking for migration existence: %v", err)
			}

			if err := runMigration(ctx, tx, mig); err != nil {
				return err
			}

			if _, err := tx.ExecContext(ctx, `insert into migrations (idx, at) values ($1, datetime('now'));`, mig.Idx); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func runMigration(ctx context.Context, tx *sql.Tx, mig migration) error {
	if mig.SQL != "" {
		if _, err := tx.ExecContext(ctx, mig.SQL); err != nil {
			return err
		}
	}

	if mig.AfterFunc != nil {
		if err := mig.AfterFunc(ctx, tx); err != nil {
			return err
		}
	}

	return nil
}
