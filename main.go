package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/justinas/nosurf"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/discovery"
	oidcm "github.com/lstoll/oidc/middleware"
	"github.com/oklog/run"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("no IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("non 200 response found")

	//go:embed web/public/*
	staticFiles embed.FS
)

func main() {
	// this is optional, ignore when it doesn't exist
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		fatalf("load .env file: %v", err)
	}

	debug := flag.Bool("debug", false, "Enable debug logging")

	addr := flag.String("http", "127.0.0.1:8085", "Run the IDP server on the given host:port.")
	configFile := flag.String("config", "config.json", "Path to the config file.")
	enroll := flag.Bool("enroll", false, "Enroll a user into the system.")
	email := flag.String("email", "", "Email address for the user.")
	fullname := flag.String("fullname", "", "Full name of the user.")
	activate := flag.Bool("activate", false, "Activate an enrolled user.")
	userID := flag.String("user-id", uuid.NewString(), "Immutable and unique user identifier to enroll or activate.")

	flag.Parse()

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

	st, err := newStorage(ctx, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", cfg.Database))
	if err != nil {
		fatalf("open database at %s: %v", cfg.Database, err)
	}

	if *enroll {
		if *userID == "" {
			fatal("required flag missing: user-id")
		}
		if *email == "" {
			fatal("required flag missing: email")
		}
		if *fullname == "" {
			fatal("required flag missing: fullname")
		}

		if err := enrollUser(ctx, st, *userID, *email, *fullname); err != nil {
			fatalf("enroll user: %v", err)
		}
		return
	} else if *activate {
		if *userID == "" {
			fatal("required flag missing: user-id")
		}

		if err := activateUser(ctx, st, *userID); err != nil {
			fatalf("ativate user: %v", err)
		}
		return
	}

	if *addr == "" {
		fatal("required flag missing: http")
	}

	// TODO(sr) Eventually this will support >1 issuer.
	issuer := cfg.Issuer[0]

	ks, err := newDerivedKeyset(cfg.EncryptionKey, cfg.PrevEncryptionKey...)
	if err != nil {
		fatalf("derive keyset: %v", err)
	}
	err = serve(ctx, st, ks, issuer, cfg.OIDCRotationInterval, cfg.OIDCMaxAge, *addr)
	if err != nil {
		fatalf("start server: %v", err)
	}
}

func serve(ctx context.Context, storage *storage, keyset *derivedKeyset, issuer issuerConfig, oidcRotateInterval, oidcMaxAge time.Duration, addr string) error {
	encryptor := newEncryptor[[]byte](keyset.dbCurr, keyset.dbPrev...)

	oidcrotator := &dbRotator[rotatableRSAKey, *rotatableRSAKey]{
		db:             storage.db,
		usage:          rotatorUsageOIDC,
		rotateInterval: oidcRotateInterval,
		maxAge:         oidcMaxAge,
		newFn: func() (*rotatableRSAKey, error) {
			return newRotatableRSAKey(encryptor)
		},
	}
	if err := oidcrotator.RotateIfNeeded(ctx); err != nil {
		return err
	}

	oidcSigner := &oidcSigner{
		rotator:   oidcrotator,
		encryptor: encryptor,
	}

	oidcmd := discovery.ProviderMetadata{
		Issuer:                issuer.URL.String(),
		JWKSURI:               issuer.URL.String() + "/keys",
		AuthorizationEndpoint: issuer.URL.String() + "/auth",
		TokenEndpoint:         issuer.URL.String() + "/token",
	}
	keysh := discovery.NewKeysHandler(oidcSigner, 1*time.Hour)
	discoh, err := discovery.NewConfigurationHandler(&oidcmd, discovery.WithCoreDefaults())
	if err != nil {
		return fmt.Errorf("configuring metadata handler: %w", err)
	}

	clients := &multiClients{
		sources: []core.ClientSource{
			&staticClients{
				clients: issuer.Client,
			},
		},
	}

	oidcsvr, err := core.New(&core.Config{
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, storage, clients, oidcSigner)
	if err != nil {
		return fmt.Errorf("failed to create OIDC server instance: %w", err)
	}

	webSessMgr := &sessionManager{
		st:                  storage,
		sessionValidityTime: 24 * time.Hour, // TODO - configure
	}

	mux := http.NewServeMux()

	mux.Handle("/keys", keysh)
	mux.Handle("/.well-known/openid-configuration", discoh)

	heh := &httpErrHandler{}

	// TODO - usernameless via resident keys would be nice, but need to
	// see what support is like.
	rrk := false
	wn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: issuer.URL.Hostname(), // Display Name for your site
		RPID:          issuer.URL.Hostname(), // Generally the FQDN for your site
		RPOrigin:      issuer.URL.String(),   // The origin URL for WebAuthn requests
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			RequireResidentKey: &rrk,
		},
	})
	if err != nil {
		return fmt.Errorf("configuring webauthn: %w", err)
	}

	// start configuration of webauthn manager
	mgr := &webauthnManager{
		store:    storage,
		webauthn: wn,
		oidcMiddleware: &oidcm.Handler{
			Issuer:       issuer.URL.String(),
			ClientID:     uuid.New().String(), // TODO - something that will live beyond restarts
			ClientSecret: uuid.New().String(),
			BaseURL:      issuer.URL.String(),
			RedirectURL:  issuer.URL.String() + "/local-oidc-callback",
			SessionStore: &sessionShim{},
			SessionName:  "webauthn-manager",
		},
		csrfMiddleware: nosurf.NewPure,
		// admins: p.Webauthn.AdminSubjects, // TODO - google account id
		acrs: nil,
	}
	// this is a dumb hack, because we use the middleware super
	// restrictively but it needs to catch it's callback.
	mux.Handle("/local-oidc-callback", mgr.oidcMiddleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should never get here?"))
	})))

	clients.sources = append([]core.ClientSource{
		&staticClients{
			clients: []clientConfig{
				{
					ClientID:     mgr.oidcMiddleware.ClientID,
					ClientSecret: []string{mgr.oidcMiddleware.ClientSecret},
					RedirectURL:  []string{mgr.oidcMiddleware.RedirectURL},
				},
			},
		},
	}, clients.sources...)

	mgr.AddHandlers(mux)

	svr := oidcServer{
		issuer:          issuer.URL.String(),
		oidcsvr:         oidcsvr,
		eh:              heh,
		tokenValidFor:   15 * time.Minute,
		refreshValidFor: 12 * time.Hour,
		// upstreamPolicy:  []byte(ucp),
		webauthn: wn,
		store:    storage,
		storage:  storage,
	}

	pubContent, err := fs.Sub(fs.FS(staticFiles), "web")
	if err != nil {
		return fmt.Errorf("creating public subfs: %w", err)
	}
	fs := http.FileServer(http.FS(pubContent))
	mux.Handle("/public/", fs)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := storage.db.Ping(); err != nil {
			slog.Error("health check: ping database", logErr(err))
			http.Error(w, "unhealthy", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("OK"))
	})

	svr.AddHandlers(mux)

	var g run.Group

	g.Add(run.SignalHandler(ctx, os.Interrupt))

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

	rotInt := make(chan struct{}, 1)
	g.Add(func() error {
		slog.Info("starting rotator", slog.Duration("interval", time.Minute))
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := oidcrotator.RotateIfNeeded(ctx); err != nil {
					return err
				}
			case <-rotInt:
				return nil
			}
		}
	}, func(error) {
		rotInt <- struct{}{}
	})

	return g.Run()
}

func enrollUser(ctx context.Context, storage *storage, userID, email, fullname string) error {
	ekey := uuid.NewString()

	if _, err := storage.CreateUser(ctx, &WebauthnUser{
		ID:            userID,
		Email:         email,
		FullName:      fullname,
		Activated:     false,
		EnrollmentKey: ekey,
	}); err != nil {
		return fmt.Errorf("adding user: %w", err)
	}

	fmt.Printf("user enrollment key: %s\n", ekey)
	fmt.Printf("Enroll at: /registration?user_id=%s&enrollment_token=%s\n", userID, ekey)

	return nil
}

func activateUser(ctx context.Context, storage *storage, userID string) error {
	u, ok, err := storage.GetUserByID(ctx, userID, true)
	if err != nil {
		return fmt.Errorf("getting user %s: %w", userID, err)
	}
	if !ok {
		return fmt.Errorf("user not found: %s", userID)
	}

	u.EnrollmentKey = ""
	u.Activated = true

	if err := storage.UpdateUser(ctx, u); err != nil {
		return fmt.Errorf("updaing user %s: %w", userID, err)
	}

	fmt.Println("Done.")

	return nil
}

func fatal(s string) {
	fmt.Fprintf(os.Stderr, "webauthn-oidc-idp: %s\n", s)
	os.Exit(1)
}

func fatalf(s string, args ...any) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("webauthn-oidc-idp: %s\n", s), args...)
	os.Exit(1)
}

func logErr(err error) slog.Attr {
	return slog.Any("error", err)
}
