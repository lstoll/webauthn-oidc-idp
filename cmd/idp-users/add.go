package main

import (
	"context"
	"log"

	"github.com/lstoll/idp/storage"
	"github.com/spf13/cobra"
)

func addCmd() *cobra.Command {
	var (
		username string
		email    string
		name     string
		groups   []string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a user to the system",
	}

	cmd.Flags().StringVar(&username, "username", "", "Username for user")
	cmd.MarkFlagRequired("username")
	cmd.Flags().StringVar(&email, "email", "", "E-Mail for user")
	cmd.MarkFlagRequired("email")
	cmd.Flags().StringVar(&name, "name", "", "Display name for user")
	cmd.MarkFlagRequired("name")
	cmd.Flags().StringSliceVar(&groups, "groups", []string{}, "Groups for user")

	cmd.Run = func(cmd *cobra.Command, args []string) {
		s := getStore()

		us := &storage.UserStore{Storage: s}

		if err := us.UpsertUser(context.TODO(), username, name, email, groups); err != nil {
			log.Fatalf("Failed to upsert user [%+v]", err)
		}
		log.Print("Done.")
	}

	return cmd
}
