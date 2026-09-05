package admin

import (
	"database/sql"
	"fmt"

	"lds.li/passidp/internal/storage"
)

// Stores holds opened credential and enrollment stores for admin operations.
type Stores struct {
	Enrollments *storage.EnrollmentStore
	Credentials *storage.CredentialFile
	sqlDB       *sql.DB
}

// OpenState opens the SQLite state database for enrollment operations.
func OpenState(statePath string) (*Stores, error) {
	sqlDB, err := storage.Open(storage.StateSQLitePath(statePath))
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}

	return &Stores{
		Enrollments: storage.NewEnrollmentStore(sqlDB),
		sqlDB:       sqlDB,
	}, nil
}

// OpenStores opens the credential file and SQLite state database.
func OpenStores(credentialStorePath, statePath string) (*Stores, error) {
	credStore, err := OpenCredentials(credentialStorePath)
	if err != nil {
		return nil, err
	}

	sqlDB, err := storage.Open(storage.StateSQLitePath(statePath))
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}

	return &Stores{
		Enrollments: storage.NewEnrollmentStore(sqlDB),
		Credentials: credStore,
		sqlDB:       sqlDB,
	}, nil
}

// OpenCredentials opens the credential store file.
func OpenCredentials(credentialStorePath string) (*storage.CredentialFile, error) {
	credStore, err := storage.NewCredentialFile(credentialStorePath)
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	return credStore, nil
}

// Close closes the underlying database connection.
func (s *Stores) Close() error {
	if s.sqlDB == nil {
		return nil
	}
	return s.sqlDB.Close()
}
