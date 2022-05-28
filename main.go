package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("No IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("Non 200 Response found")
)

type globalCfg struct {
	storage *storage
	keyset  *derivedKeyset
}

func main() {
	ctx := context.Background()
	l := logrus.New()

	// this is optional, ignore when it doesn't exist
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		l.WithError(err).Fatal("Error loading .env file")
	}

	kingpin.Version(getVersion())

	app := kingpin.New("idp", "A webauthn IDP.")
	dbPath := app.Flag("db-path", "Path to database file").Envar("DB_PATH").Default("db/idp.db").String()
	securePassphrase := app.Flag("secure-passphrase", "Passphrase for DB encryption").Envar("SECURE_PASSPHRASE").Required().String()
	prevSecurePassphrases := app.Flag("prev-secure-passphrases", "Passphrase(s) previously used for DB encryption, to decrypt").Envar("SECURE_PASSPHRASES_PREV").Strings()

	serveCmd, serveRun := serveCommand(app)

	cmdName := kingpin.MustParse(app.Parse(os.Args[1:]))

	// common initialization
	ks, err := newDerivedKeyset(*securePassphrase, *prevSecurePassphrases...)
	if err != nil {
		l.WithError(err).Fatal("failed deriving keyset")
	}

	st, err := newStorage(ctx, l, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", *dbPath))
	if err != nil {
		l.WithError(err).Fatal("failed to create storage")
	}

	gcfg := &globalCfg{
		keyset:  ks,
		storage: st,
	}
	_ = gcfg

	var runErr error
	switch cmdName {
	// Register user
	case serveCmd.FullCommand():
		runErr = serveRun(ctx, gcfg)
	default:
		panic("should not happen, kingpin should handle this")
	}
	if runErr != nil {
		l.WithError(runErr).Fatal()
	}
}

func getVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		panic("couldn't read runtime build info")
	}

	var (
		rev   string
		dirty bool
	)
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	verStr := bi.Main.Version + " (rev: " + rev
	if dirty {
		verStr += ", dirty"
	}
	verStr += ")"

	return verStr
}
