package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

func migrateData(ctx context.Context, filedb *DB, sqldb *sql.DB) error {
	tx, err := sqldb.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	q := queries.New(tx)

	var migrated bool
	filedb.f.Read(func(data *schema) {
		migrated = data.UsersMigrated
	})
	if migrated {
		return nil
	}

	slog.InfoContext(ctx, "migrating users to SQL database")

	var migErr error
	filedb.f.Read(func(data *schema) {
		for _, user := range data.Users {
			var (
				userHasNonUUIDID bool
				userID           uuid.UUID
			)
			if err := uuid.Validate(user.ID); err != nil {
				userHasNonUUIDID = true
				userID = must(uuid.NewV7())
			} else {
				userID = uuid.MustParse(user.ID)
			}

			up := queries.CreateUserParams{
				ID:             userID,
				Email:          user.Email,
				FullName:       user.FullName,
				WebauthnHandle: must(uuid.NewRandom()),
			}
			if userHasNonUUIDID {
				up.OverrideSubject = sql.NullString{
					String: user.ID,
					Valid:  true,
				}
			}

			if err := q.CreateUser(context.Background(), up); err != nil {
				migErr = fmt.Errorf("failed to create user %s: %w", user.ID, err)
				return
			}

			for _, cred := range user.Credentials {
				cd, err := json.Marshal(cred.Credential)
				if err != nil {
					migErr = fmt.Errorf("failed to marshal credential %s: %w", cred.ID, err)
					return
				}

				params := queries.CreateUserCredentialParams{
					ID:             must(uuid.NewV7()),
					CredentialID:   cred.ID,
					UserID:         userID,
					Name:           cred.Name,
					CredentialData: cd,
					CreatedAt:      cred.AddedAt,
				}
				if err := q.CreateUserCredential(context.Background(), params); err != nil {
					migErr = fmt.Errorf("failed to create user credential %s: %w", cred.ID, err)
					return
				}
			}
		}
	})
	if migErr != nil {
		return fmt.Errorf("failed to migrate users: %w", migErr)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	if err := filedb.f.Write(func(data *schema) error {
		data.UsersMigrated = true
		return nil
	}); err != nil {
		return fmt.Errorf("failed to note migration: %w", err)
	}

	return nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
