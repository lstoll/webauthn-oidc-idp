package main

import (
	"database/sql"
	"log"
	"os"
	"sync"

	"github.com/lstoll/idp/storage/sqlstore"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "idp-users",
}

var (
	dbURL string
)

func main() {
	rootCmd = &cobra.Command{Use: "idp-users"}

	defaultDB := os.Getenv("DATABASE_URL")
	if defaultDB == "" {
		defaultDB = "postgres://localhost/idp_dev?sslmode=disable"
	}
	rootCmd.PersistentFlags().StringVar(&dbURL, "dburl", defaultDB, "URL of the database to talk to")

	rootCmd.AddCommand(addCmd())
	rootCmd.AddCommand(listAuthCmd())
	rootCmd.AddCommand(activeAuthCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

var (
	store *sqlstore.Store
	dbMu  sync.Once
)

func getStore() *sqlstore.Store {
	dbMu.Do(func() {
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Failed to open database %v", err)
		}
		s, err := sqlstore.New(logrus.New(), db)
		if err != nil {
			log.Fatalf("Error setting up store [%+v]", err)
		}
		store = s
	})
	return store
}
