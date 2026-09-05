package admincli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
	"uuid"

	"lds.li/passidp/internal/admin"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

type AddCredentialCmd struct {
	UserID   string        `required:"" help:"ID of user to add credential to."`
	Validity time.Duration `default:"15m" help:"How long the enrollment URL remains valid."`

	Output io.Writer `kong:"-"`
}

func (c *AddCredentialCmd) Run(ctx context.Context, cfg *config.Config, paths Paths) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id: %w", err)
	}

	stores, err := admin.OpenState(paths.StatePath)
	if err != nil {
		return err
	}
	defer stores.Close()

	if c.Validity <= 0 {
		c.Validity = storage.DefaultEnrollmentValidity
	}

	enrollment, err := admin.CreateEnrollment(cfg, stores.Enrollments, userID, c.Validity)
	if err != nil {
		return err
	}

	fmt.Fprintf(c.Output, "Enrollment ID: %s\n", enrollment.EnrollmentID)
	fmt.Fprintf(c.Output, "Enrollment Key: %s\n", enrollment.EnrollmentKey)
	fmt.Fprintf(c.Output, "Valid until: %s\n", enrollment.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(c.Output, "Enroll at: %s\n", enrollment.EnrollmentURL)
	return nil
}
