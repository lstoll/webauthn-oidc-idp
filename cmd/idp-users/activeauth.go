package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/lstoll/idp/webauthn/webauthnpb"

	"github.com/lstoll/idp/storage"
	"github.com/spf13/cobra"
)

func activeAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate-authenticator <authenticator>",
		Short: "Activate an authenticator on a user",
		Args:  cobra.ExactArgs(1),
	}

	cmd.Run = func(cmd *cobra.Command, args []string) {
		s := getStore()

		us := &storage.UserStore{Storage: s}

		aID, err := base64.StdEncoding.DecodeString(args[0])
		if err != nil {
			log.Fatalf("Failed to base64 decode id [%+v]", err)
		}
		auth, err := us.GetAuthenticator(context.TODO(), &webauthnpb.GetAuthenticatorRequest{AuthenticatorId: aID})
		if err != nil {
			log.Fatalf("Failed to get use authenticator [%+v]", err)
		}
		log.Printf("Are you sure you want to activate user %s challenge %s (y/n): ", auth.Authenticator.Username, auth.Authenticator.ActivationChallenge)

		var resp string
		_, _ = fmt.Scanln(&resp)

		if resp != "y" && resp != "yes" {
			log.Fatal("Not confirmed, aborting")
		}

		auth.Authenticator.Active = true

		if _, err := us.UpdateAuthenticator(context.TODO(), &webauthnpb.UpdateAuthenticatorRequest{
			Authenticator: auth.Authenticator,
		}); err != nil {
			log.Fatal("Error marking authenticator active [%+v]", err)
		}

		log.Print("Done.")
	}

	return cmd
}
