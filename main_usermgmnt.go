package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"gopkg.in/alecthomas/kingpin.v2"
)

func addUserCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *storage) error) {
	adduser := app.Command("adduser", "Add a enrollable user to the system")

	id := adduser.Flag("user-id", "Unique ID for this user, immutable").Default(uuid.NewString()).String()
	email := adduser.Flag("email", "Email address for the user").Required().String()
	fullname := adduser.Flag("fullname", "Full name of the user").Required().String()

	return adduser, func(ctx context.Context, storage *storage) error {
		ekey := uuid.NewString()

		if _, err := storage.CreateUser(ctx, &WebauthnUser{
			ID:            *id,
			Email:         *email,
			FullName:      *fullname,
			Activated:     false,
			EnrollmentKey: ekey,
		}); err != nil {
			return fmt.Errorf("adding user: %w", err)
		}

		fmt.Printf("user enrollment key: %s\n", ekey)
		fmt.Printf("Enroll at: /registration?user_id=%s&enrollment_token=%s\n", *id, ekey)

		return nil
	}
}

func activateUserCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *storage) error) {
	activateUser := app.Command("activate-user", "Activate an enrolled user")

	id := activateUser.Flag("user-id", "Unique ID for this user, immutable").Required().String()

	return activateUser, func(ctx context.Context, storage *storage) error {
		u, ok, err := storage.GetUserByID(ctx, *id, true)
		if err != nil {
			return fmt.Errorf("getting user %s: %w", *id, err)
		}
		if !ok {
			return fmt.Errorf("no such user %s", *id)
		}

		u.EnrollmentKey = ""
		u.Activated = true

		if err := storage.UpdateUser(ctx, u); err != nil {
			return fmt.Errorf("updaing user %s: %w", *id, err)
		}

		fmt.Println("Done.")

		return nil
	}
}
