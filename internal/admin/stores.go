package admin

import (
	"database/sql"
	"fmt"

	"lds.li/passidp/internal/storage"
)

// Stores holds opened enrollment state for admin operations.
type Stores struct {
	Enrollments *storage.EnrollmentStore
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

// Close closes the underlying database connection.
func (s *Stores) Close() error {
	if s.sqlDB == nil {
		return nil
	}
	return s.sqlDB.Close()
}
