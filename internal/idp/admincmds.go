package idp

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

type EnrollUserCmd struct {
	Email    string `required:"" help:"Email address for the user."`
	FullName string `required:"" help:"Full name of the user."`

	Output io.Writer `kong:"-"`
}

func (c *EnrollUserCmd) Run(ctx context.Context, db *sql.DB, issuerURL *url.URL) error {
	if c.Output == nil {
		c.Output = os.Stdout
	}

	params := queries.CreateUserParams{
		ID:             uuid.Must(uuid.NewV7()), //nolint:gosec // we're not using this for anything
		Email:          c.Email,
		FullName:       c.FullName,
		EnrollmentKey:  sql.NullString{String: uuid.NewString(), Valid: true},
		WebauthnHandle: uuid.Must(uuid.NewRandom()),
	}

	if err := queries.New(db).CreateUser(ctx, params); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	fmt.Fprintf(c.Output, "New user created: %s\n", params.ID)
	fmt.Fprintf(c.Output, "Enrollment URL: %s\n", RegistrationURL(issuerURL, params.ID.String(), params.EnrollmentKey.String))
	return nil
}

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

	fmt.Fprintf(c.Output, "Enroll at: %s\n", RegistrationURL(issuerURL, userUUID.String(), ek))
	return nil
}

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

	for _, c := range creds {
		fmt.Printf("credential: %s (added at %s)\n", c.Name, c.CreatedAt)
	}
	return nil
}
