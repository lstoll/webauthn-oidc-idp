package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

const PendingEnrollmentMaxAge = 24 * time.Hour

// EnrollmentStore persists in-progress credential enrollments in SQLite.
type EnrollmentStore struct {
	db *sql.DB
}

// PendingEnrollment is an in-progress passkey registration.
type PendingEnrollment struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	EnrollmentKey   string
	CreatedAt       time.Time
	ConfirmationKey string
	CredentialID    []byte
	CredentialData  json.RawMessage
	Name            string
}

// NewEnrollmentStore returns a SQL-backed pending enrollment store.
func NewEnrollmentStore(sqlDB *sql.DB) *EnrollmentStore {
	return &EnrollmentStore{db: sqlDB}
}

// EnrollmentHasCredential reports whether a pending enrollment has a registered passkey.
func EnrollmentHasCredential(row PendingEnrollment) bool {
	return len(row.CredentialData) > 0
}

// EnrollmentCredential decodes the registered passkey, or nil if not yet registered.
func EnrollmentCredential(row PendingEnrollment) (*webauthn.Credential, error) {
	if !EnrollmentHasCredential(row) {
		return nil, nil
	}

	var credential webauthn.Credential
	if err := json.Unmarshal(row.CredentialData, &credential); err != nil {
		return nil, fmt.Errorf("unmarshal credential: %w", err)
	}
	return &credential, nil
}

func marshalEnrollmentCredential(credential *webauthn.Credential) (json.RawMessage, error) {
	data, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}
	return data, nil
}

func (e *EnrollmentStore) CreatePendingEnrollment(userID uuid.UUID) (PendingEnrollment, error) {
	enrollment := PendingEnrollment{
		ID:            uuid.New(),
		UserID:        userID,
		EnrollmentKey: uuid.New().String(),
		CreatedAt:     time.Now(),
	}

	_, err := e.db.ExecContext(context.Background(), `
		INSERT INTO pending_enrollments (id, user_id, enrollment_key, created_at)
		VALUES (?, ?, ?, ?)`,
		enrollment.ID, enrollment.UserID, enrollment.EnrollmentKey, enrollment.CreatedAt)
	if err != nil {
		return PendingEnrollment{}, fmt.Errorf("insert enrollment: %w", err)
	}
	return enrollment, nil
}

func (e *EnrollmentStore) GetPendingEnrollmentByKey(enrollmentKey string) (PendingEnrollment, error) {
	row, err := scanEnrollment(e.db.QueryRowContext(context.Background(), enrollmentSelect+`
		WHERE enrollment_key = ?`, enrollmentKey))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PendingEnrollment{}, fmt.Errorf("enrollment not found")
		}
		return PendingEnrollment{}, fmt.Errorf("get enrollment by key: %w", err)
	}
	return row, nil
}

func (e *EnrollmentStore) GetPendingEnrollmentByID(enrollmentID uuid.UUID) (PendingEnrollment, error) {
	row, err := scanEnrollment(e.db.QueryRowContext(context.Background(), enrollmentSelect+`
		WHERE id = ?`, enrollmentID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PendingEnrollment{}, fmt.Errorf("enrollment not found")
		}
		return PendingEnrollment{}, fmt.Errorf("get enrollment by id: %w", err)
	}
	return row, nil
}

func (e *EnrollmentStore) UpdatePendingEnrollment(enrollmentID uuid.UUID, credentialID []byte, credentialData *webauthn.Credential, name string, confirmationKey string) error {
	enrollment, err := e.GetPendingEnrollmentByID(enrollmentID)
	if err != nil {
		return err
	}

	if EnrollmentHasCredential(enrollment) {
		return fmt.Errorf("enrollment already completed - a passkey has already been registered for this enrollment")
	}

	credentialJSON, err := marshalEnrollmentCredential(credentialData)
	if err != nil {
		return err
	}

	_, err = e.db.ExecContext(context.Background(), `
		UPDATE pending_enrollments
		SET confirmation_key = ?, credential_id = ?, credential_data = ?, name = ?
		WHERE id = ?`,
		confirmationKey, credentialID, credentialJSON, name, enrollmentID)
	return err
}

func (e *EnrollmentStore) ConfirmPendingEnrollment(enrollmentID uuid.UUID, confirmationKey string) (PendingEnrollment, error) {
	enrollment, err := e.GetPendingEnrollmentByID(enrollmentID)
	if err != nil {
		return PendingEnrollment{}, err
	}

	if enrollment.ConfirmationKey == "" || enrollment.ConfirmationKey != confirmationKey {
		return PendingEnrollment{}, fmt.Errorf("invalid confirmation key")
	}
	if !EnrollmentHasCredential(enrollment) {
		return PendingEnrollment{}, fmt.Errorf("enrollment not completed")
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
		enrollments = append(enrollments, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	return enrollments, nil
}

func (e *EnrollmentStore) GarbageCollectPendingEnrollments() (int, error) {
	cutoff := time.Now().Add(-PendingEnrollmentMaxAge)
	result, err := e.db.ExecContext(context.Background(), `
		DELETE FROM pending_enrollments WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired enrollments: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired enrollments: %w", err)
	}
	return int(deleted), nil
}

const enrollmentSelect = `
	SELECT id, user_id, enrollment_key, created_at, confirmation_key, credential_id, credential_data, name
	FROM pending_enrollments`

type enrollmentScanner interface {
	Scan(dest ...any) error
}

func scanEnrollment(s enrollmentScanner) (PendingEnrollment, error) {
	var (
		e               PendingEnrollment
		confirmationKey sql.NullString
		name            sql.NullString
		credentialData  []byte
	)
	err := s.Scan(
		&e.ID,
		&e.UserID,
		&e.EnrollmentKey,
		&e.CreatedAt,
		&confirmationKey,
		&e.CredentialID,
		&credentialData,
		&name,
	)
	if err != nil {
		return PendingEnrollment{}, err
	}
	e.ConfirmationKey = confirmationKey.String
	e.Name = name.String
	e.CredentialData = credentialData
	return e, nil
}
