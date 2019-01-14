package sqlstore

import (
	"database/sql"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	bindata "github.com/golang-migrate/migrate/source/go_bindata"
	"github.com/lstoll/idp/storage/sqlstore/migrations"
	"github.com/pkg/errors"
)

func migratorInstance(db *sql.DB) (*migrate.Migrate, error) {
	// wrap assets into Resource
	s := bindata.Resource(migrations.AssetNames(),
		func(name string) ([]byte, error) {
			return migrations.Asset(name)
		})

	src, err := bindata.WithInstance(s)
	if err != nil {
		return nil, errors.Wrap(err, "Error building migration source from bindata")
	}

	pdb, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return nil, errors.Wrap(err, "Error getting database driver instance")
	}
	m, err := migrate.NewWithInstance("go-bindata", src, "db", pdb)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating migrator")
	}
	return m, nil
}

func migrateDB(db *sql.DB) error {
	m, err := migratorInstance(db)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && errors.Cause(err) != migrate.ErrNoChange {
		return errors.Wrap(err, "Failed to migrate database")
	}
	return nil
}

// MigrateDown will run all the down migrations on the given DB. This is mostly
// useful for testing.
func MigrateDown(db *sql.DB) error {
	m, err := migratorInstance(db)
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil {
		return errors.Wrap(err, "Failed to migrate database")
	}
	return nil
}
