package admincli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type AddCredentialCmd struct {
	UserID string `required:"" help:"ID of user to add credential to."`

	Output io.Writer `kong:"-"`
}

func (c *AddCredentialCmd) Run(ctx context.Context, db *sql.DB, issuerURL *url.URL) error {
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

	ek := uuid.NewString()

	if err := q.SetUserEnrollmentKey(ctx, sql.NullString{String: ek, Valid: true}, userUUID); err != nil {
		return fmt.Errorf("set user enrollment key: %w", err)
	}

	fmt.Fprintf(c.Output, "Enroll at: %s\n", fmt.Sprintf("%s/registration?enrollment_token=%s&user_id=%s", issuerURL.String(), ek, userUUID.String()))
	return nil
}
