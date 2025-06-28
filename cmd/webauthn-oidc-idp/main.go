package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"
	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/common/version"
)

const progname = "webauthn-oidc-idp"

func init() {
	if version.Version == "" {
		version.Version = "devel"
	}
	if version.Branch == "" {
		version.Branch = "unknown"
	}
	prometheus.MustRegister(versioncollector.NewCollector(strings.ReplaceAll(progname, "-", "_")))
}

func main() {
	// Root flags that apply to all commands
	rootFlags := flag.NewFlagSet("root", flag.ExitOnError)
	debug := rootFlags.Bool("debug", false, "Enable debug logging")
	configFile := rootFlags.String("config", "config.json", "Path to the config file.")

	// Command1 flags
	cmd1Flags := flag.NewFlagSet("command1", flag.ExitOnError)
	cmd1String := cmd1Flags.String("string", "default", "A string flag for command1")
	cmd1Int := cmd1Flags.Int("int", 42, "An integer flag for command1")

	// Command2 flags
	cmd2Flags := flag.NewFlagSet("command2", flag.ExitOnError)
	cmd2Bool := cmd2Flags.Bool("bool", false, "A boolean flag for command2")
	cmd2Float := cmd2Flags.Float64("float", 3.14, "A float flag for command2")

	// Process environment variables for all flagsets
	setFlagsFromEnv(rootFlags)
	setFlagsFromEnv(cmd1Flags)
	setFlagsFromEnv(cmd2Flags)

	// Parse root flags first
	rootFlags.Parse(os.Args[1:])

	// Check if we have a subcommand
	if len(rootFlags.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  command1    First sample command\n")
		fmt.Fprintf(os.Stderr, "  command2    Second sample command\n")
		os.Exit(1)
	}

	// Get the subcommand
	subcommand := rootFlags.Args()[0]

	switch subcommand {
	case "command1":
		// Parse command1 flags with remaining args
		cmd1Flags.Parse(rootFlags.Args()[1:])
		fmt.Printf("Executing command1\n")
		fmt.Printf("  Root debug flag: %v\n", *debug)
		fmt.Printf("  Root config file: %s\n", *configFile)
		fmt.Printf("  Command1 string flag: %s\n", *cmd1String)
		fmt.Printf("  Command1 int flag: %d\n", *cmd1Int)

	case "command2":
		// Parse command2 flags with remaining args
		cmd2Flags.Parse(rootFlags.Args()[1:])
		fmt.Printf("Executing command2\n")
		fmt.Printf("  Root debug flag: %v\n", *debug)
		fmt.Printf("  Root config file: %s\n", *configFile)
		fmt.Printf("  Command2 bool flag: %v\n", *cmd2Bool)
		fmt.Printf("  Command2 float flag: %f\n", *cmd2Float)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcommand)
		fmt.Fprintf(os.Stderr, "Available commands: command1, command2\n")
		os.Exit(1)
	}
}

// setFlagsFromEnv sets flag values from environment variables with IDP_ prefix
func setFlagsFromEnv(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		envName := "IDP_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if val, ok := os.LookupEnv(envName); ok {
			if err := f.Value.Set(val); err != nil {
				fatalf("set flag %s from env %s: %v", f.Name, envName, err)
			}
		}
	})
}

func oldMain() {
	ver := flag.Bool("version", false, "Print the version and exit.")
	debug := flag.Bool("debug", false, "Enable debug logging")
	addr := flag.String("http", "127.0.0.1:8085", "Run the IDP server on the given host:port.")
	metrics := flag.String("metrics", "", "Expose Prometheus metrics on the given host:port.")
	configFile := flag.String("config", "config.json", "Path to the config file.")
	enroll := flag.Bool("enroll", false, "Enroll a user into the system.")
	email := flag.String("email", "", "Email address for the user.")
	fullname := flag.String("fullname", "", "Full name of the user.")
	addCredential := flag.Bool("add-credential", false, "Generate a new credential enrollment URL for a user")
	userID := flag.String("user-id", "", "ID of user to add credential to.")
	listCredential := flag.Bool("list-credentials", false, "List credentials for the user-id")
	dbPath := flag.String("db-path", "", "Path to SQLite database file. Overrides config file setting.")

	// Set flags from environment variables with IDP_ prefix
	flag.VisitAll(func(f *flag.Flag) {
		envName := "IDP_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if val, ok := os.LookupEnv(envName); ok {
			if err := f.Value.Set(val); err != nil {
				fatalf("set flag %s from env %s: %v", f.Name, envName, err)
			}
		}
	})

	flag.Parse()

	if *ver {
		fmt.Fprintln(os.Stdout, version.Print(progname))
		os.Exit(0)
	}

	b, err := os.ReadFile(*configFile)
	if err != nil {
		fatalf("read config file: %v", err)
	}
	var cfg config
	if err := loadConfig(b, &cfg); err != nil {
		fatalf("load config file: %v", err)
	}

	var level slog.Leveler
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx := context.Background()

	// legacy database
	db, err := idp.OpenDB(cfg.Database)
	if err != nil {
		fatalf("open database at %s: %v", cfg.Database, err)
	}

	if *dbPath == "" {
		fatal("required flag missing: db")
	}

	sqldb, err := sql.Open("sqlite3", *dbPath+"?_journal=WAL")
	if err != nil {
		fatalf("open database: %v", err)
	}
	defer sqldb.Close()

	if _, err := sqldb.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		fatalf("enable WAL mode: %v", err)
	}

	if _, err := sqldb.Exec("PRAGMA busy_timeout=5000;"); err != nil {
		fatalf("set busy timeout: %v", err)
	}

	if err := dbpkg.Migrate(ctx, sqldb); err != nil {
		fatalf("run migrations: %v", err)
	}

	if *enroll {
		if *email == "" {
			fatal("required flag missing: email")
		}
		if *fullname == "" {
			fatal("required flag missing: fullname")
		}

		params := queries.CreateUserParams{
			ID:             must(uuid.NewV7()),
			Email:          *email,
			FullName:       *fullname,
			EnrollmentKey:  sql.NullString{String: uuid.NewString(), Valid: true},
			WebauthnHandle: must(uuid.NewRandom()),
		}

		if err := queries.New(sqldb).CreateUser(ctx, params); err != nil {
			fatalf("create user: %v", err)
		}

		fmt.Printf("New user created: %s\n", params.ID)
		fmt.Printf("Enroll at: %s\n", idp.RegistrationURL(cfg.Issuer[0].URL, params.ID.String(), params.EnrollmentKey.String))
		return
	} else if *addCredential {
		if *userID == "" {
			fatal("required flag missing: user-id")
		}

		userUUID, err := uuid.Parse(*userID)
		if err != nil {
			fatalf("parse user-id: %v", err)
		}

		q := queries.New(sqldb)

		_, err = q.GetUser(ctx, userUUID)
		if err != nil {
			fatalf("get user %s: %w", userID, err)
		}

		ek := uuid.NewString()

		if err := q.SetUserEnrollmentKey(ctx, sql.NullString{String: ek, Valid: true}, userUUID); err != nil {
			fatalf("set user enrollment key: %v", err)
		}

		fmt.Printf("Enroll at: %s\n", idp.RegistrationURL(cfg.Issuer[0].URL, userUUID.String(), ek))
		return
	} else if *listCredential {
		if *userID == "" {
			fatal("required flag missing: user-id")
		}
		userUUID, err := uuid.Parse(*userID)
		if err != nil {
			fatalf("parse user-id: %v", err)
		}

		q := queries.New(sqldb)

		_, err = q.GetUser(ctx, userUUID)
		if err != nil {
			fatalf("get user %s: %w", userID, err)
		}

		creds, err := q.GetUserCredentials(ctx, userUUID)
		if err != nil {
			fatalf("get user credentials: %v", err)
		}

		for _, c := range creds {
			fmt.Printf("credential: %s (added at %s)\n", c.Name, c.CreatedAt)
		}
		return
	}

	if *addr == "" {
		fatal("required flag missing: http")
	}

	issuer := cfg.Issuer[0]

	if err := idp.ServeCmd(ctx, sqldb, db, issuer.URL, issuer.Clients, *addr, *metrics); err != nil {
		fatalf("start server: %v", err)
	}
}

func fatal(s string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progname, s)
	os.Exit(1)
}

func fatalf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("%s: %s\n", progname, s), args...)
	os.Exit(1)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
