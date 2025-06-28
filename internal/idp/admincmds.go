package idp

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type EnrollArgs struct {
	Email    string
	FullName string
	Issuer   *url.URL
}

type EnrollResult struct {
	UserID        uuid.UUID
	EnrollmentURL *url.URL
}

func EnrollCmd(ctx context.Context, db *sql.DB, args EnrollArgs) (*EnrollResult, error) {
	if args.Email == "" {
		return nil, fmt.Errorf("required flag missing: email")
	}
	if args.FullName == "" {
		return nil, fmt.Errorf("required flag missing: fullname")
	}

	params := queries.CreateUserParams{
		ID:             must(uuid.NewV7()),
		Email:          args.Email,
		FullName:       args.FullName,
		EnrollmentKey:  sql.NullString{String: uuid.NewString(), Valid: true},
		WebauthnHandle: must(uuid.NewRandom()),
	}

	if err := queries.New(db).CreateUser(ctx, params); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &EnrollResult{
		UserID:        params.ID,
		EnrollmentURL: RegistrationURL(args.Issuer, params.ID.String(), params.EnrollmentKey.String),
	}, nil
}

type AddCredentialArgs struct {
	UserID string
	Issuer *url.URL
}

func AddCredentialCmd(ctx context.Context, db *sql.DB, args AddCredentialArgs) error {
	if args.UserID == "" {
		return fmt.Errorf("required flag missing: user-id")
	}

	userUUID, err := uuid.Parse(args.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	q := queries.New(db)

	_, err = q.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", args.UserID, err)
	}

	ek := uuid.NewString()

	if err := q.SetUserEnrollmentKey(ctx, sql.NullString{String: ek, Valid: true}, userUUID); err != nil {
		return fmt.Errorf("set user enrollment key: %w", err)
	}

	fmt.Printf("Enroll at: %s\n", RegistrationURL(args.Issuer, userUUID.String(), ek))
	return nil
}

type ListCredentialsArgs struct {
	UserID string
}

func ListCredentialsCmd(ctx context.Context, db *sql.DB, args ListCredentialsArgs) error {
	if args.UserID == "" {
		return fmt.Errorf("required flag missing: user-id")
	}
	userUUID, err := uuid.Parse(args.UserID)
	if err != nil {
		return fmt.Errorf("parse user-id: %w", err)
	}

	q := queries.New(db)

	_, err = q.GetUser(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", args.UserID, err)
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
