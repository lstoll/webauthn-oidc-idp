package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lstoll/cookiesession"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/oidc/discovery"
	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/web"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/tink-crypto/tink-go/v2/keyset"
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

	db, err := openDB(cfg.Database)
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

	if err := migrateData(ctx, db, sqldb); err != nil {
		fatalf("failed to migrate data: %v", err)
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
		fmt.Printf("Enroll at: %s\n", registrationURL(cfg.Issuer[0].URL, params.ID.String(), params.EnrollmentKey.String))
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

		fmt.Printf("Enroll at: %s\n", registrationURL(cfg.Issuer[0].URL, userUUID.String(), ek))
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

	if err := serve(ctx, sqldb, db, issuer, *addr, *metrics); err != nil {
		fatalf("start server: %v", err)
	}
}

func serve(ctx context.Context, sqldb *sql.DB, db *DB, issuer issuerConfig, addr, metrics string) error {
	var g run.Group

	cookieHandles, oidcHandles, err := initKeysets(ctx, sqldb, g)
	if err != nil {
		return fmt.Errorf("initializing keysets: %w", err)
	}

	oidcmd := discovery.DefaultCoreMetadata(issuer.URL.String())
	oidcmd.AuthorizationEndpoint = issuer.URL.String() + "/auth"
	oidcmd.TokenEndpoint = issuer.URL.String() + "/token"
	oidcmd.ScopesSupported = []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile, "offline"}
	oidcmd.UserinfoEndpoint = issuer.URL.String() + "/userinfo"

	discoh, err := discovery.NewConfigurationHandler(oidcmd, oidcHandles)
	if err != nil {
		return fmt.Errorf("configuring metadata handler: %w", err)
	}

	oidcsvr, err := core.New(&core.Config{
		Issuer:           issuer.URL.String(),
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, db.SessionManager(), &staticclients.Clients{Clients: issuer.Clients}, oidcHandles)
	if err != nil {
		return fmt.Errorf("failed to create OIDC server instance: %w", err)
	}

	webSessMgr, err := cookiesession.New[webSession]("idp", func() *keyset.Handle {
		h, err := cookieHandles.Handle(context.Background())
		if err != nil {
			// we should not hit this, the load comes from the DB TODO(lstoll)
			// get a consistent way of looking up handles.
			slog.Error("refreshing keyset", logErr(err))
			os.Exit(1)
		}
		return h
	}, cookiesession.Options{
		MaxAge:   0, // Scopes it to browser lifecycle, which I think is good for now
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Insecure: issuer.URL.Hostname() == "localhost", // safari is picky about this
	})
	if err != nil {
		return fmt.Errorf("creating cookie session for webauthn: %w", err)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/openid-configuration", discoh)
	mux.Handle("GET /.well-known/jwks.json", discoh)

	heh := &httpErrHandler{}

	wn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: issuer.URL.Hostname(), // Display Name for your site
		RPID:          issuer.URL.Hostname(), // Generally the FQDN for your site
		RPOrigins: []string{
			issuer.URL.String(),
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			RequireResidentKey: ptr(true),
		},
	})
	if err != nil {
		return fmt.Errorf("configuring webauthn: %w", err)
	}

	// start configuration of webauthn manager
	mgr := &webauthnManager{
		db:       db,
		webauthn: wn,
		sessmgr:  webSessMgr,
		queries:  queries.New(sqldb),
	}

	mgr.AddHandlers(mux)

	svr := oidcServer{
		issuer:          issuer.URL.String(),
		oidcsvr:         oidcsvr,
		eh:              heh,
		tokenValidFor:   15 * time.Minute,
		refreshValidFor: 12 * time.Hour,
		sessmgr:         webSessMgr,
		// upstreamPolicy:  []byte(ucp),
		webauthn: wn,
		db:       db,
		queries:  queries.New(sqldb),
	}

	fs := http.FileServer(http.FS(web.PublicFiles))
	mux.Handle("/public/", fs)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		return err
	}
	mux.HandleFunc("/reloaddb", func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !loopback.Contains(net.ParseIP(ip)) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if err := db.Reload(); err != nil {
			slog.ErrorContext(r.Context(), "database reload failed", slog.Any("error", err))
			http.Error(w, fmt.Sprintf("reload failed: %v", err), http.StatusInternalServerError)
		} else {
			slog.InfoContext(r.Context(), "database reloaded")
		}
	})

	svr.AddHandlers(mux)

	g.Add(run.SignalHandler(ctx, os.Interrupt, unix.SIGTERM))

	// this will always try and create a session for discovery and stuff,
	// but we shouldn't save it. but, we need it for logging and stuff. TODO
	// at some point consider splitting the middleware, but then we might
	// need to dup the middleware wrap or something.
	hh := baseMiddleware(mux, webSessMgr)

	hs := &http.Server{
		Addr:    addr,
		Handler: hh,
	}

	g.Add(func() error {
		slog.Info("server listing", slog.String("addr", "http://"+addr))
		if err := hs.ListenAndServe(); err != nil {
			return fmt.Errorf("serving http: %v", err)
		}
		return nil
	}, func(error) {
		// new context for this, parent is likely already shut down
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})

	{
		if metrics != "" {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			promsrv := &http.Server{Addr: metrics, Handler: mux}

			g.Add(func() error {
				slog.Info("metrics server listing", slog.String("addr", "http://"+metrics))
				if err := promsrv.ListenAndServe(); err != nil {
					return fmt.Errorf("serving metrics: %v", err)
				}
				return nil
			}, func(error) {
				promsrv.Close()
			})
		}
	}

	return g.Run()
}

func registrationURL(iss *url.URL, userID string, enrollmentKey string) *url.URL {
	u := *iss
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u2, err := u.Parse("/registration")
	if err != nil {
		panic(err)
	}
	q := u2.Query()
	q.Add("user_id", userID)
	q.Add("enrollment_token", enrollmentKey)
	u2.RawQuery = q.Encode()
	return u2
}

// reloadDB tells the server running on addr to reload its database from disk.
func reloadDB(addr string) {
	resp, err := http.Get("http://" + addr + "/reloaddb")
	if err != nil {
		fatalf("database reload failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fatalf("database reload failed: %s", string(b))
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

func logErr(err error) slog.Attr {
	return slog.Any("error", err)
}

func ptr[T any](v T) *T {
	return &v
}
