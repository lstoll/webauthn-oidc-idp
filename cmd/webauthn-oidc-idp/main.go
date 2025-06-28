package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Root flags that apply to all commands
	rootFlags := flag.NewFlagSet("root", flag.ExitOnError)
	debug := rootFlags.Bool("debug", false, "Enable debug logging")
	configFile := rootFlags.String("config", "config.json", "Path to the config file. If not specified, db-path and issuer-host must be specified.")
	dbPath := rootFlags.String("db-path", "", "Path to database file, for single tenant mode. Not needed if config set")
	issuerHost := rootFlags.String("issuer-host", "", "Host name of the issuer, for single tenant mode. Not needed if config set")
	selectedHost := rootFlags.String("selected-host", "", "In multi-tenant mode, the host to select for administrative operations. Not used for serving.")

	serveArgs := struct {
		Addr    string
		Metrics string
	}{}
	serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
	serveFlags.StringVar(&serveArgs.Addr, "http", "127.0.0.1:8085", "Run the IDP server on the given host:port.")
	serveFlags.StringVar(&serveArgs.Metrics, "metrics", "", "Expose Prometheus metrics on the given host:port.")

	enrollFlags := flag.NewFlagSet("enroll-user", flag.ExitOnError)
	enrollArgs := idp.EnrollArgs{}
	enrollFlags.StringVar(&enrollArgs.Email, "email", "", "Email address for the user.")
	enrollFlags.StringVar(&enrollArgs.FullName, "fullname", "", "Full name of the user.")

	addCredentialFlags := flag.NewFlagSet("add-credential", flag.ExitOnError)
	addCredentialArgs := idp.AddCredentialArgs{}
	addCredentialFlags.StringVar(&addCredentialArgs.UserID, "user-id", "", "ID of user to add credential to.")

	listCredentialsFlags := flag.NewFlagSet("list-credentials", flag.ExitOnError)
	listCredentialsArgs := idp.ListCredentialsArgs{}
	listCredentialsFlags.StringVar(&listCredentialsArgs.UserID, "user-id", "", "ID of user to list credentials for.")

	// Process environment variables for all flagsets
	setFlagsFromEnv(rootFlags)
	setFlagsFromEnv(serveFlags)
	setFlagsFromEnv(enrollFlags)
	setFlagsFromEnv(addCredentialFlags)
	setFlagsFromEnv(listCredentialsFlags)

	// Parse root flags first
	_ = rootFlags.Parse(os.Args[1:])

	// Check if we have a subcommand
	if len(rootFlags.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  serve    Serve the IDP\n")
		fmt.Fprintf(os.Stderr, "  version  Print version information\n")
		fmt.Fprintf(os.Stderr, "  enroll-user  Enroll a user into the system\n")
		fmt.Fprintf(os.Stderr, "  add-credential  Add a credential to a user\n")
		fmt.Fprintf(os.Stderr, "  list-credentials  List credentials for a user\n")
		os.Exit(1)
	}

	var level slog.Leveler
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Get the subcommand
	subcommand := rootFlags.Args()[0]

	var cfg *config

	if *configFile == "" {
		if *dbPath == "" || *issuerHost == "" {
			fatal("required flag missing: db-path or issuer-host")
		}
		// set up directly.
		*selectedHost = *issuerHost
		// TODO - if we're in this case, the active tenant would be this one.
		// Need a way to signal to the later code to not check the flag.
		fatal("TODO: enable simple single tenant mode when we no longer depend on legacy config clients")
	}
	if *configFile != "" {
		if *dbPath != "" || *issuerHost != "" {
			fatal("db-path and issuer-host cannot be used with config file")
		}
		b, err := os.ReadFile(*configFile)
		if err != nil {
			fatalf("read config file %s: %v", *configFile, err)
		}
		c, err := loadConfig(b)
		if err != nil {
			fatalf("load config file %s: %v", *configFile, err)
		}
		cfg = c
	}

	if len(cfg.Tenants) != 1 {
		fatal("TODO: enable multi-tenant mode")
	}

	// load all the database for the tenants
	var activeTenant *configTenant
	for _, tenant := range cfg.Tenants {
		var err error
		tenant.db, err = sql.Open("sqlite3", tenant.DBPath+"?_journal=WAL")
		if err != nil {
			fatalf("open database %s for tenant %s: %v", tenant.DBPath, tenant.Hostname, err)
		}

		if _, err := tenant.db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			fatalf("enable WAL mode: %v", err)
		}

		if _, err := tenant.db.Exec("PRAGMA busy_timeout=5000;"); err != nil {
			fatalf("set busy timeout: %v", err)
		}

		if err := dbpkg.Migrate(ctx, tenant.db); err != nil {
			fatalf("run migrations: %v", err)
		}

		tenant.legacyDB, err = idp.OpenDB(tenant.ImportDBPath)
		if err != nil {
			fatalf("open legacy database for tenant %s at %s: %v", tenant.Hostname, tenant.ImportDBPath, err)
		}

		if tenant.Hostname == *selectedHost {
			activeTenant = tenant
		}
	}

	if activeTenant == nil && subcommand != "serve" {
		fatalf("no active tenant found for host %s", *selectedHost)
	}

	switch subcommand {
	case "serve":
		_ = serveFlags.Parse(rootFlags.Args()[1:])
		// TODO - this should loop, and set up an IDP for each one.
		serveTenant := cfg.Tenants[0]

		if err := idp.ServeCmd(ctx, serveTenant.db, serveTenant.legacyDB, serveTenant.issuerURL, serveTenant.ImportedClients, serveArgs.Addr, serveArgs.Metrics); err != nil {
			fatalf("start server: %v", err)
		}

	case "version":
		fmt.Fprintln(os.Stdout, version.Print(progname))
		os.Exit(0)

	case "enroll-user":
		_ = enrollFlags.Parse(rootFlags.Args()[1:])
		enrollArgs.Issuer = activeTenant.issuerURL
		result, err := idp.EnrollCmd(ctx, activeTenant.db, enrollArgs)
		if err != nil {
			fatalf("enroll user: %v", err)
		}
		fmt.Printf("New user created: %s\n", result.UserID)
		fmt.Printf("Enrollment URL: %s\n", result.EnrollmentURL)

	case "add-credential":
		_ = addCredentialFlags.Parse(rootFlags.Args()[1:])
		addCredentialArgs.Issuer = activeTenant.issuerURL
		if err := idp.AddCredentialCmd(ctx, activeTenant.db, addCredentialArgs); err != nil {
			fatalf("add credential: %v", err)
		}

	case "list-credentials":
		_ = listCredentialsFlags.Parse(rootFlags.Args()[1:])
		if err := idp.ListCredentialsCmd(ctx, activeTenant.db, listCredentialsArgs); err != nil {
			fatalf("list credentials: %v", err)
		}

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

func fatal(s string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", progname, s)
	os.Exit(1)
}

func fatalf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("%s: %s\n", progname, s), args...)
	os.Exit(1)
}
