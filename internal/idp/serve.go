package idp

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/oidc/discovery"
	"github.com/lstoll/web"
	"github.com/lstoll/web/csp"
	"github.com/lstoll/web/session"
	"github.com/lstoll/web/session/sqlkv"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	webcontent "github.com/lstoll/webauthn-oidc-idp/web"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

// ServeCmd implements the serving command for an IDP.
func ServeCmd(ctx context.Context, sqldb *sql.DB, db *DB, issuerURL *url.URL, clients []staticclients.Client, addr, metrics string) error {
	var g run.Group

	if err := migrateData(ctx, db, sqldb); err != nil {
		return fmt.Errorf("failed to migrate data: %v", err)
	}

	_, oidcHandles, err := initKeysets(ctx, sqldb, g)
	if err != nil {
		return fmt.Errorf("initializing keysets: %w", err)
	}

	sesskv := sqlkv.New(sqldb, &sqlkv.Opts{
		TableName: "web_sessions",
		Dialect:   sqlkv.SQLite,
	})

	sessionManager, err := session.NewKVManager(sesskv, nil)
	if err != nil {
		return fmt.Errorf("creating session manager: %w", err)
	}

	cspOpts := []csp.HandlerOpt{
		csp.DefaultSrc(`'none'`),
		csp.ImgSrc(`'self'`),
		csp.ConnectSrc(`'self'`),
		csp.FontSrc(`'self'`),
		csp.BaseURI(`'self'`),
		csp.FrameAncestors(`'none'`),
		// end defaults
		csp.ScriptSrc("'self' 'unsafe-inline'"), // TODO - use a nonce
		csp.StyleSrc("'self' 'unsafe-inline'"),  // TODO - use a nonce
	}

	websvr, err := web.NewServer(&web.Config{
		BaseURL:        issuerURL,
		SessionManager: sessionManager,
		Static:         webcontent.PublicFiles, // TODO - lstoll/web should not panic when not set
		CSPOpts:        cspOpts,
	})
	if err != nil {
		return fmt.Errorf("creating web server: %w", err)
	}
	// TODO - websvr should respect Fly-Request-ID

	oidcmd := discovery.DefaultCoreMetadata(issuerURL.String())
	oidcmd.AuthorizationEndpoint = issuerURL.String() + "/auth"
	oidcmd.TokenEndpoint = issuerURL.String() + "/token"
	oidcmd.ScopesSupported = []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile, "offline"}
	oidcmd.UserinfoEndpoint = issuerURL.String() + "/userinfo"

	discoh, err := discovery.NewConfigurationHandler(oidcmd, oidcHandles)
	if err != nil {
		return fmt.Errorf("configuring metadata handler: %w", err)
	}

	oidcsvr, err := core.New(&core.Config{
		Issuer:           issuerURL.String(),
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, db.SessionManager(), &staticclients.Clients{Clients: clients}, oidcHandles)
	if err != nil {
		return fmt.Errorf("failed to create OIDC server instance: %w", err)
	}

	websvr.HandleRaw("GET /.well-known/openid-configuration", discoh)
	websvr.HandleRaw("GET /.well-known/jwks.json", discoh)

	wn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: issuerURL.Hostname(), // Display Name for your site
		RPID:          issuerURL.Hostname(), // Generally the FQDN for your site
		RPOrigins: []string{
			issuerURL.String(),
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
		queries:  queries.New(sqldb),
	}

	mgr.AddHandlers(websvr)

	svr := oidcServer{
		issuer:          issuerURL.String(),
		oidcsvr:         oidcsvr,
		tokenValidFor:   15 * time.Minute,
		refreshValidFor: 12 * time.Hour,
		// upstreamPolicy:  []byte(ucp),
		webauthn: wn,
		db:       db,
		queries:  queries.New(sqldb),
	}

	fs := http.FileServer(http.FS(webcontent.PublicFiles))
	websvr.HandleRaw("/public/", fs)

	websvr.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	svr.AddHandlers(websvr)

	g.Add(run.SignalHandler(ctx, os.Interrupt, unix.SIGTERM))

	hs := &http.Server{
		Addr:    addr,
		Handler: websvr,
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

func ptr[T any](v T) *T {
	return &v
}
