package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"gopkg.in/alecthomas/kingpin.v2"
)

func addUserCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *globalCfg) error) {
	adduser := app.Command("adduser", "Add a enrollable user to the system")

	id := adduser.Flag("user-id", "Unique ID for this user, immutable").Default(uuid.NewString()).String()
	email := adduser.Flag("email", "Email address for the user").Required().String()
	fullname := adduser.Flag("fullname", "Full name of the user").Required().String()

	return adduser, func(ctx context.Context, gcfg *globalCfg) error {

		ekey := uuid.NewString()

		if _, err := gcfg.storage.CreateUser(ctx, &WebauthnUser{
			ID:            *id,
			Email:         *email,
			FullName:      *fullname,
			Activated:     false,
			EnrollmentKey: ekey,
		}); err != nil {
			return fmt.Errorf("adding user: %w", err)
		}

		ctxLog(ctx).Infof("User enrollment key: %s", ekey)
		ctxLog(ctx).Infof("Enroll at: /registration?user_id=%s&enrollment_token=%s", *id, ekey)

		return nil
	}
}

func activateUserCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *globalCfg) error) {
	activateUser := app.Command("activate-user", "Activate an enrolled user")

	id := activateUser.Flag("user-id", "Unique ID for this user, immutable").Required().String()

	return activateUser, func(ctx context.Context, gcfg *globalCfg) error {

		u, ok, err := gcfg.storage.GetUserByID(ctx, *id, true)
		if err != nil {
			return fmt.Errorf("getting user %s: %w", *id, err)
		}
		if !ok {
			return fmt.Errorf("no such user %s", *id)
		}

		u.EnrollmentKey = ""
		u.Activated = true

		if err := gcfg.storage.UpdateUser(ctx, u); err != nil {
			return fmt.Errorf("updaing user %s: %w", *id, err)
		}

		ctxLog(ctx).Info("Done.")

		return nil
	}
}
