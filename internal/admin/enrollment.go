package admin

import (
	"fmt"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/webauthn"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

// EnrollmentInfo is returned when a pending enrollment is created.
type EnrollmentInfo struct {
	EnrollmentID  string
	EnrollmentKey string
	EnrollmentURL string
	ExpiresAt     time.Time
}

// CreateEnrollment starts a short-lived passkey enrollment for a user.
func CreateEnrollment(cfg *config.Config, enrollments *storage.EnrollmentStore, userID uuid.UUID, validity time.Duration) (*EnrollmentInfo, error) {
	if _, err := cfg.Users.GetUser(userID); err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	enrollment, err := enrollments.CreatePendingEnrollment(userID, validity)
	if err != nil {
		return nil, fmt.Errorf("create enrollment: %w", err)
	}

	enrollmentURL := fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s",
		cfg.Issuer, enrollment.EnrollmentKey, userID.String())

	return &EnrollmentInfo{
		EnrollmentID:  enrollment.ID.String(),
		EnrollmentKey: enrollment.EnrollmentKey,
		EnrollmentURL: enrollmentURL,
		ExpiresAt:     enrollment.ExpiresAt,
	}, nil
}

// CompleteEnrollment consumes a pending enrollment and writes the passkey.
func CompleteEnrollment(
	cfg *config.Config,
	enrollments *storage.EnrollmentStore,
	credStore *storage.CredentialFile,
	userID, enrollmentID uuid.UUID,
	credential *webauthn.Credential,
	name string,
) error {
	record, err := storage.EncodePasskeyRecord(credential)
	if err != nil {
		return fmt.Errorf("encode passkey record: %w", err)
	}
	user, err := cfg.Users.GetUser(userID)
	if err != nil {
		return err
	}

	enrollment, err := enrollments.ConsumePendingEnrollment(enrollmentID)
	if err != nil {
		return fmt.Errorf("consume enrollment: %w", err)
	}
	if enrollment.UserID != userID {
		return fmt.Errorf("enrollment user_id mismatch")
	}

	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		cs.AddPasskey(userID, user.PasskeyHandleAliases(), &storage.Passkey{
			ID:        uuid.New(),
			Record:    record,
			Name:      name,
			CreatedAt: time.Now(),
		})
		return nil
	}); err != nil {
		return fmt.Errorf("write credential: %w", err)
	}
	return nil
}
