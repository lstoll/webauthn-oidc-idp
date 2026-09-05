package admincli

import (
	"context"
	"fmt"
	"io"
	"os"
	"uuid"

	"lds.li/passidp/internal/admin"
	"lds.li/passidp/internal/config"
)

type ConfirmCredentialCmd struct {
	UserID          string `required:"" help:"ID of user the credential belongs to."`
	EnrollmentID    string `required:"" help:"ID of the enrollment to confirm."`
	ConfirmationKey string `required:"" help:"Confirmation key from the enrollment."`

	Output io.Writer `kong:"-"`
}

func (c *ConfirmCredentialCmd) Run(ctx context.Context, cfg *config.Config, paths Paths) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("invalid user_id: %w", err)
	}

	enrollmentID, err := uuid.Parse(c.EnrollmentID)
	if err != nil {
		return fmt.Errorf("invalid enrollment_id: %w", err)
	}

	stores, err := admin.OpenStores(paths.CredentialStorePath, paths.StatePath)
	if err != nil {
		return err
	}
	defer stores.Close()

	confirmed, err := admin.ConfirmEnrollment(cfg, stores.Enrollments, stores.Credentials, userID, enrollmentID, c.ConfirmationKey)
	if err != nil {
		return err
	}

	fmt.Fprintf(c.Output, "Credential confirmed and activated successfully!\n")
	fmt.Fprintf(c.Output, "Name: %s\n", confirmed.Name)
	fmt.Fprintf(c.Output, "User ID: %s\n", confirmed.UserID)
	return nil
}
