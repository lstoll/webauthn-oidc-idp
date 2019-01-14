package main

import (
	"context"
	"encoding/base64"
	"log"

	"github.com/lstoll/idp/webauthn/webauthnpb"

	"github.com/lstoll/idp/storage"
	"github.com/spf13/cobra"
)

func listAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-authenticators <user>",
		Short: "List authenticators in the system",
		Args:  cobra.ExactArgs(1),
	}

	cmd.Run = func(cmd *cobra.Command, args []string) {
		s := getStore()

		us := &storage.UserStore{Storage: s}

		auths, err := us.UserAuthenticators(context.TODO(), &webauthnpb.GetUserRequest{Username: args[0]})
		if err != nil {
			log.Fatalf("Failed to get use authenticatorsr [%+v]", err)
		}
		for _, a := range auths.Authenticators {
			log.Printf("ID %s Active %t Challenge %s", base64.StdEncoding.EncodeToString(a.Id), a.Active, a.ActivationChallenge)
		}
		log.Print("Done.")
	}

	return cmd
}
