package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type ListCredentialsCmd struct {
	UserID string `required:"" help:"ID of user to list credentials for."`

	Output io.Writer `kong:"-"`
}

func (c *ListCredentialsCmd) Run(ctx context.Context, db *sql.DB) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	userUUID, err := uuid.Parse(c.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	q := queries.New(db)

	_, err = q.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", c.UserID, err)
	}

	creds, err := q.GetUserCredentials(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user credentials: %w", err)
	}

	for _, cred := range creds {
		fmt.Fprintf(c.Output, "credential: %s (added at %s)\n", cred.Name, cred.CreatedAt)
	}
	return nil
}
