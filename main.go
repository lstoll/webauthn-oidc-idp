package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/joho/godotenv"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("no IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("non 200 response found")
)

type globalCfg struct {
	storage *storage
	keyset  *derivedKeyset
}

func main() {
	ctx := context.Background()

	// this is optional, ignore when it doesn't exist
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		kingpin.Fatalf("load .env file: %w", err)
	}

	kingpin.Version(getVersion())

	app := kingpin.New("idp", "A webauthn IDP.")
	dbPath := app.Flag("db-path", "Path to database file").Envar("DB_PATH").Default("db/idp.db").String()
	securePassphrase := app.Flag("secure-passphrase", "Passphrase for DB encryption").Envar("SECURE_PASSPHRASE").Required().String()
	prevSecurePassphrases := app.Flag("prev-secure-passphrases", "Passphrase(s) previously used for DB encryption, to decrypt").Envar("SECURE_PASSPHRASES_PREV").Strings()
	debug := app.Flag("debug", "Debug logging output").Envar("DEBUG").Bool()

	serveCmd, serveRun := serveCommand(app)
	addUserCmd, addUserRun := addUserCommand(app)
	activateUserCmd, activateUserRun := activateUserCommand(app)

	cmdName := kingpin.MustParse(app.Parse(os.Args[1:]))

	var level slog.Leveler
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// common initialization
	ks, err := newDerivedKeyset(*securePassphrase, *prevSecurePassphrases...)
	if err != nil {
		kingpin.Fatalf("derive keyset: %w", err)
	}

	st, err := newStorage(ctx, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", *dbPath))
	if err != nil {
		kingpin.Fatalf("open database at %s: %w", *dbPath, err)
	}

	gcfg := &globalCfg{
		keyset:  ks,
		storage: st,
	}

	var runErr error
	switch cmdName {
	// Register user
	case serveCmd.FullCommand():
		runErr = serveRun(ctx, gcfg)
	case addUserCmd.FullCommand():
		runErr = addUserRun(ctx, gcfg)
	case activateUserCmd.FullCommand():
		runErr = activateUserRun(ctx, gcfg)
	default:
		panic("should not happen, kingpin should handle this")
	}
	if runErr != nil {
		kingpin.Fatalf("webauthn-oidc-idp: %w", err)
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

func logErr(err error) slog.Attr {
	return slog.Any("error", err)
}
