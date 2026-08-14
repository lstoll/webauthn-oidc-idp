package admincli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"lds.li/passidp/internal/admin"
)

type DeleteCredentialCmd struct {
	CredentialID string `required:"" help:"ID of the credential to delete."`

	Output io.Writer `kong:"-"`
}

func (c *DeleteCredentialCmd) Run(ctx context.Context, paths Paths) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	credentialID, err := uuid.Parse(c.CredentialID)
	if err != nil {
		return fmt.Errorf("invalid credential_id: %w", err)
	}

	credStore, err := admin.OpenCredentials(paths.CredentialStorePath)
	if err != nil {
		return err
	}

	if err := admin.DeleteCredential(credStore, credentialID); err != nil {
		return err
	}

	fmt.Fprintf(c.Output, "Credential deleted successfully.\n")
	return nil
}
