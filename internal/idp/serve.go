package idp

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/cookiesession"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/oidc/discovery"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/web"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/sys/unix"
)

// ServeCmd implements the serving command for an IDP.
func ServeCmd(ctx context.Context, sqldb *sql.DB, db *DB, issuerURL *url.URL, clients []staticclients.Client, addr, metrics string) error {
	var g run.Group

	if err := migrateData(ctx, db, sqldb); err != nil {
		return fmt.Errorf("failed to migrate data: %v", err)
	}

	cookieHandles, oidcHandles, err := initKeysets(ctx, sqldb, g)
	if err != nil {
		return fmt.Errorf("initializing keysets: %w", err)
	}

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

	webSessMgr, err := cookiesession.New[webSession]("idp", func() *keyset.Handle {
		h, err := cookieHandles.Handle(context.Background())
		if err != nil {
			// we should not hit this, the load comes from the DB TODO(lstoll)
			// get a consistent way of looking up handles.
			slog.Error("refreshing keyset", "err", err)
			os.Exit(1)
		}
		return h
	}, cookiesession.Options{
		MaxAge:   0, // Scopes it to browser lifecycle, which I think is good for now
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Insecure: issuerURL.Hostname() == "localhost", // safari is picky about this
	})
	if err != nil {
		return fmt.Errorf("creating cookie session for webauthn: %w", err)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /.well-known/openid-configuration", discoh)
	mux.Handle("GET /.well-known/jwks.json", discoh)

	heh := &httpErrHandler{}

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
		sessmgr:  webSessMgr,
		queries:  queries.New(sqldb),
	}

	mgr.AddHandlers(mux)

	svr := oidcServer{
		issuer:          issuerURL.String(),
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

func ptr[T any](v T) *T {
	return &v
}
