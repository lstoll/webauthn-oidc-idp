package admin

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

// EnrollmentInfo is returned when a pending enrollment is created.
type EnrollmentInfo struct {
	EnrollmentID  string
	EnrollmentKey string
	EnrollmentURL string
}

// CreateEnrollment starts a pending passkey enrollment for a user.
func CreateEnrollment(cfg *config.Config, enrollments *storage.EnrollmentStore, userID uuid.UUID) (*EnrollmentInfo, error) {
	if _, err := cfg.Users.GetUser(userID); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	enrollment, err := enrollments.CreatePendingEnrollment(userID)
	if err != nil {
		return nil, fmt.Errorf("create enrollment: %w", err)
	}

	enrollmentURL := fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s",
		cfg.Issuer, enrollment.EnrollmentKey, userID.String())

	return &EnrollmentInfo{
		EnrollmentID:  enrollment.ID.String(),
		EnrollmentKey: enrollment.EnrollmentKey,
		EnrollmentURL: enrollmentURL,
	}, nil
}

// ConfirmedCredential is returned when an enrollment is confirmed.
type ConfirmedCredential struct {
	Name   string
	UserID string
}

// ConfirmEnrollment finalizes a pending enrollment and writes the credential.
func ConfirmEnrollment(
	cfg *config.Config,
	enrollments *storage.EnrollmentStore,
	credStore *storage.CredentialFile,
	userID, enrollmentID uuid.UUID,
	confirmationKey string,
) (*ConfirmedCredential, error) {
	enrollment, err := enrollments.ConfirmPendingEnrollment(enrollmentID, confirmationKey)
	if err != nil {
		return nil, fmt.Errorf("confirm enrollment: %w", err)
	}

	if enrollment.UserID != userID {
		return nil, fmt.Errorf("enrollment user_id mismatch")
	}

	credentialData, err := storage.EnrollmentCredential(enrollment)
	if err != nil {
		return nil, err
	}
	if credentialData == nil {
		return nil, fmt.Errorf("enrollment not completed")
	}

	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		record, err := storage.EncodePasskeyRecord(credentialData)
		if err != nil {
			return fmt.Errorf("encode passkey record: %w", err)
		}
		user, err := cfg.Users.GetUser(userID)
		if err != nil {
			return err
		}
		cs.AddPasskey(userID, user.PasskeyHandleAliases(), &storage.Passkey{
			ID:        uuid.New(),
			Record:    record,
			Name:      enrollment.Name,
			CreatedAt: time.Now(),
		})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("write credential: %w", err)
	}

	return &ConfirmedCredential{
		Name:   enrollment.Name,
		UserID: enrollment.UserID.String(),
	}, nil
}
