package idp

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/oidc/discovery"
	"github.com/lstoll/web"
	"github.com/lstoll/web/csp"
	"github.com/lstoll/web/proxyhdrs"
	"github.com/lstoll/web/requestid"
	"github.com/lstoll/web/session"
	"github.com/lstoll/web/session/sqlkv"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/internal/webcommon"
	"github.com/oklog/run"
)

// NewIDP creates a new IDP server for the given params.
func NewIDP(ctx context.Context, g *run.Group, sqldb *sql.DB, db *DB, issuerURL *url.URL, clients []staticclients.Client) (http.Handler, error) {
	if err := migrateData(ctx, db, sqldb); err != nil {
		return nil, fmt.Errorf("failed to migrate data: %v", err)
	}

	oidcHandles, err := initKeysets(ctx, sqldb)
	if err != nil {
		return nil, fmt.Errorf("initializing keysets: %w", err)
	}

	sesskv := sqlkv.New(sqldb, &sqlkv.Opts{
		TableName: "web_sessions",
		Dialect:   sqlkv.SQLite,
	})

	sessionManager, err := session.NewKVManager(sesskv, nil)
	if err != nil {
		return nil, fmt.Errorf("creating session manager: %w", err)
	}

	cspOpts := []csp.HandlerOpt{
		csp.DefaultSrc(`'none'`),
		csp.ImgSrc(`'self'`),
		csp.ConnectSrc(`'self'`),
		csp.FontSrc(`'self'`),
		csp.BaseURI(`'self'`),
		csp.FrameAncestors(`'none'`),
		// end defaults
		csp.ScriptSrc("'self' https://ajax.googleapis.com 'unsafe-inline'"), // TODO - use a nonce
		csp.StyleSrc("'self' 'unsafe-inline'"),                              // TODO - use a nonce
	}

	websvr, err := web.NewServer(&web.Config{
		BaseURL:        issuerURL,
		SessionManager: sessionManager,
		Static:         webcommon.Static, // TODO - lstoll/web should not panic when not set
		CSPOpts:        cspOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("creating web server: %w", err)
	}
	if err := websvr.BaseMiddleware.Replace(web.MiddlewareRequestIDName, (&requestid.Middleware{
		TrustedHeaders: []string{"Fly-Request-ID"},
	}).Handler); err != nil {
		return nil, fmt.Errorf("replacing request id middleware: %w", err)
	}
	remoteIPMiddleware := &proxyhdrs.RemoteIP{
		ForwardedIPHeader: "Fly-Client-IP",
	}
	websvr.BaseMiddleware.Prepend(web.MiddlewareRequestLogName, remoteIPMiddleware.Handle)

	forceTLSMiddleware := &proxyhdrs.ForceTLS{
		ForwardedProtoHeader: "X-Forwarded-Proto",
	}
	forceTLSMiddleware.AllowBypass("GET /healthz")
	if err := websvr.BaseMiddleware.InsertAfter(web.MiddlewareRequestLogName, forceTLSMiddleware.Handle); err != nil {
		return nil, fmt.Errorf("inserting force tls middleware: %w", err)
	}

	oidcmd := discovery.DefaultCoreMetadata(issuerURL.String())
	oidcmd.AuthorizationEndpoint = issuerURL.String() + "/auth"
	oidcmd.TokenEndpoint = issuerURL.String() + "/token"
	oidcmd.ScopesSupported = []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile, "offline"}
	oidcmd.UserinfoEndpoint = issuerURL.String() + "/userinfo"

	discoh, err := discovery.NewConfigurationHandler(oidcmd, oidcHandles)
	if err != nil {
		return nil, fmt.Errorf("configuring metadata handler: %w", err)
	}

	oidcsvr, err := core.New(&core.Config{
		Issuer:           issuerURL.String(),
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, db.SessionManager(), &staticclients.Clients{Clients: clients}, oidcHandles)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC server instance: %w", err)
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
		return nil, fmt.Errorf("configuring webauthn: %w", err)
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

	// TODO - web should handle all this.
	fs := http.FileServer(http.FS(webcommon.Static))
	websvr.HandleRaw("/public/", http.StripPrefix("/public/", fs))

	websvr.HandleRaw("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))

	svr.AddHandlers(websvr)

	return websvr, nil
}

func ptr[T any](v T) *T {
	return &v
}
