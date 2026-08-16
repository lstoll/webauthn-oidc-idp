package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"uuid"
)

const DefaultEnrollmentValidity = 15 * time.Minute

// EnrollmentStore persists in-progress credential enrollments in SQLite.
type EnrollmentStore struct {
	db *sql.DB
}

// PendingEnrollment is a short-lived passkey enrollment token.
type PendingEnrollment struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	EnrollmentKey string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// NewEnrollmentStore returns a SQL-backed pending enrollment store.
func NewEnrollmentStore(sqlDB *sql.DB) *EnrollmentStore {
	return &EnrollmentStore{db: sqlDB}
}

func (e *EnrollmentStore) CreatePendingEnrollment(userID uuid.UUID, validity time.Duration) (PendingEnrollment, error) {
	if validity <= 0 {
		return PendingEnrollment{}, fmt.Errorf("enrollment validity must be positive")
	}
	now := time.Now()
	enrollment := PendingEnrollment{
		ID:            uuid.New(),
		UserID:        userID,
		EnrollmentKey: rand.Text(),
		CreatedAt:     now,
		ExpiresAt:     now.Add(validity),
	}

	_, err := e.db.ExecContext(context.Background(), `
		INSERT INTO pending_enrollments (id, user_id, enrollment_key, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		enrollment.ID, enrollment.UserID, enrollment.EnrollmentKey, enrollment.CreatedAt, enrollment.ExpiresAt)
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("insert enrollment: %w", err)
	}
	return enrollment, nil
}

func (e *EnrollmentStore) GetPendingEnrollmentByKey(enrollmentKey string) (PendingEnrollment, error) {
	return e.getPendingEnrollment(enrollmentSelect+` WHERE enrollment_key = ?`, enrollmentKey)
}

func (e *EnrollmentStore) GetPendingEnrollmentByID(enrollmentID uuid.UUID) (PendingEnrollment, error) {
	return e.getPendingEnrollment(enrollmentSelect+` WHERE id = ?`, enrollmentID)
}

func (e *EnrollmentStore) getPendingEnrollment(query string, arg any) (PendingEnrollment, error) {
	row, err := scanEnrollment(e.db.QueryRowContext(context.Background(), query, arg))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PendingEnrollment{}, fmt.Errorf("enrollment not found")
		}
		return PendingEnrollment{}, fmt.Errorf("get enrollment: %w", err)
	}
	if row.Expired() {
		return PendingEnrollment{}, fmt.Errorf("enrollment expired")
	}
	return row, nil
}

// ConsumePendingEnrollment deletes a still-valid enrollment and returns it.
func (e *EnrollmentStore) ConsumePendingEnrollment(enrollmentID uuid.UUID) (PendingEnrollment, error) {
	enrollment, err := e.GetPendingEnrollmentByID(enrollmentID)
	if err != nil {
		return PendingEnrollment{}, err
	}

	result, err := e.db.ExecContext(context.Background(), `DELETE FROM pending_enrollments WHERE id = ?`, enrollmentID)
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("delete enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("delete enrollment: %w", err)
	}
	if rows == 0 {
		return PendingEnrollment{}, fmt.Errorf("enrollment not found")
	}
	return enrollment, nil
}

func (e *EnrollmentStore) ListPendingEnrollmentsByUser(userID uuid.UUID) ([]PendingEnrollment, error) {
	rows, err := e.db.QueryContext(context.Background(), enrollmentSelect+`
		WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	defer rows.Close()

	var enrollments []PendingEnrollment
	for rows.Next() {
		row, err := scanEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("list enrollments: %w", err)
		}
		if row.Expired() {
			continue
		}
		enrollments = append(enrollments, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	return enrollments, nil
}

func (e *EnrollmentStore) GarbageCollectPendingEnrollments() (int, error) {
	result, err := e.db.ExecContext(context.Background(), `
		DELETE FROM pending_enrollments WHERE expires_at < ?`, time.Now())
	if err != nil {
		return 0, fmt.Errorf("delete expired enrollments: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired enrollments: %w", err)
	}
	return int(deleted), nil
}

func (p PendingEnrollment) Expired() bool {
	return !p.ExpiresAt.After(time.Now())
}

const enrollmentSelect = `
	SELECT id, user_id, enrollment_key, created_at, expires_at
	FROM pending_enrollments`

type enrollmentScanner interface {
	Scan(dest ...any) error
}

func scanEnrollment(s enrollmentScanner) (PendingEnrollment, error) {
	var e PendingEnrollment
	err := s.Scan(
		&e.ID,
		&e.UserID,
		&e.EnrollmentKey,
		&e.CreatedAt,
		&e.ExpiresAt,
	)
	if err != nil {
		return PendingEnrollment{}, err
	}
	return e, nil
}
