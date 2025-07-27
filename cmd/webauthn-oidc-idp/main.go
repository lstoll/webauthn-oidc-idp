package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"golang.org/x/sys/unix"
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
	selectedIssuer := rootFlags.String("selected-issuer", "", "In multi-tenant mode, the issuer to select for administrative operations. Not used for serving.")

	serveArgs := struct {
		Addr     string
		Metrics  string
		CertFile string
		KeyFile  string
	}{}
	serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
	serveFlags.StringVar(&serveArgs.Addr, "http", "localhost:8085", "Run the IDP server on the given host:port.")
	serveFlags.StringVar(&serveArgs.Metrics, "metrics", "", "Expose Prometheus metrics on the given host:port.")
	serveFlags.StringVar(&serveArgs.CertFile, "cert-file", "", "Path to the TLS certificate file.")
	serveFlags.StringVar(&serveArgs.KeyFile, "key-file", "", "Path to the TLS key file.")

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
		fatal("config file is required")
	}

	{
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
		fatal("TODO: test multi-tenant mode")
	}

	// load all the database for the tenants
	var activeTenant *configTenant
	for _, tenant := range cfg.Tenants {
		var err error
		tenant.db, err = sql.Open("sqlite3", tenant.DBPath+"?_journal=WAL")
		if err != nil {
			fatalf("open database %s for tenant %s: %v", tenant.DBPath, tenant.Issuer, err)
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
			fatalf("open legacy database for tenant %s at %s: %v", tenant.Issuer, tenant.ImportDBPath, err)
		}

		if tenant.Issuer == *selectedIssuer {
			activeTenant = tenant
		}
	}

	if activeTenant == nil && subcommand != "serve" {
		fatalf("no active tenant found for issuer %s", *selectedIssuer)
	}

	switch subcommand {
	case "serve":
		_ = serveFlags.Parse(rootFlags.Args()[1:])

		var g run.Group
		g.Add(run.SignalHandler(ctx, os.Interrupt, unix.SIGTERM))

		mux := http.NewServeMux()

		for _, tenant := range cfg.Tenants {
			h, err := idp.NewIDP(ctx, &g, tenant.db, tenant.legacyDB, tenant.issuerURL, tenant.ImportedClients)
			if err != nil {
				fatalf("start server: %v", err)
			}

			mux.Handle(tenant.issuerURL.Hostname()+"/", h)
		}

		hs := &http.Server{
			Addr:    serveArgs.Addr,
			Handler: mux,
		}

		g.Add(func() error {
			if serveArgs.CertFile != "" && serveArgs.KeyFile != "" {
				slog.Info("server listing", slog.String("addr", "https://"+serveArgs.Addr))
				if err := hs.ListenAndServeTLS(serveArgs.CertFile, serveArgs.KeyFile); err != nil {
					return fmt.Errorf("serving https: %v", err)
				}
			} else {
				slog.Info("server listing", slog.String("addr", "http://"+serveArgs.Addr))
				if err := hs.ListenAndServe(); err != nil {
					return fmt.Errorf("serving http: %v", err)
				}
			}
			return nil
		}, func(error) {
			// new context for this, parent is likely already shut down
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_ = hs.Shutdown(ctx)
		})

		{
			if serveArgs.Metrics != "" {
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())
				promsrv := &http.Server{Addr: serveArgs.Metrics, Handler: mux}

				g.Add(func() error {
					slog.Info("metrics server listing", slog.String("addr", "http://"+serveArgs.Metrics))
					if err := promsrv.ListenAndServe(); err != nil {
						return fmt.Errorf("serving metrics: %v", err)
					}
					return nil
				}, func(error) {
					promsrv.Close()
				})
			}
		}

		mux.Handle("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("OK"))
		}))

		if err := g.Run(); err != nil {
			fatalf("run: %v", err)
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
