package idp

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/oauth2as"
	"github.com/lstoll/web"
	"github.com/lstoll/web/csp"
	"github.com/lstoll/web/proxyhdrs"
	"github.com/lstoll/web/requestid"
	"github.com/lstoll/web/session"
	"github.com/lstoll/web/session/sqlkv"
	"github.com/lstoll/webauthn-oidc-idp/internal/auth"
	"github.com/lstoll/webauthn-oidc-idp/internal/clients"
	"github.com/lstoll/webauthn-oidc-idp/internal/oidcsvr"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/internal/webcommon"
	"github.com/oklog/run"
)

// NewIDP creates a new IDP server for the given params.
func NewIDP(ctx context.Context, g *run.Group, sqldb *sql.DB, legacyDB *DB, issuerURL *url.URL, clients *clients.StaticClients) (http.Handler, error) {
	if legacyDB != nil {
		if err := migrateData(ctx, legacyDB, sqldb); err != nil {
			return nil, fmt.Errorf("failed to migrate data: %v", err)
		}
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
		webauthn: wn,
		queries:  queries.New(sqldb),
	}

	mgr.AddHandlers(websvr)

	// svr := oidcServer{
	// 	issuer:          issuerURL.String(),
	// 	oidcsvr:         legacyoidcsvr,
	// 	tokenValidFor:   15 * time.Minute,
	// 	refreshValidFor: 12 * time.Hour,
	// 	// upstreamPolicy:  []byte(ucp),
	// 	webauthn: wn,
	// 	db:       db,
	// 	queries:  queries.New(sqldb),
	// }

	// TODO - web should handle all this.
	fs := http.FileServer(http.FS(webcommon.Static))
	websvr.HandleRaw("/public/", http.StripPrefix("/public/", fs))

	auth := &auth.Authenticator{
		Webauthn: wn,
		Queries:  queries.New(sqldb),
	}
	auth.AddHandlers(websvr)

	oidchHandlers := &oidcsvr.Handlers{
		Issuer:  issuerURL.String(),
		Queries: queries.New(sqldb),
		Clients: clients,
	}

	oauth2asConfig := oauth2as.Config{
		Issuer:  issuerURL.String(),
		Storage: oidcsvr.NewSQLiteStorage(sqldb),
		Clients: clients,
		Keyset:  oidcHandles,

		TokenHandler:    oidchHandlers.TokenHandler,
		UserinfoHandler: oidchHandlers.UserinfoHandler,

		AuthorizationPath: "/authorization",
		TokenPath:         "/token",
		UserinfoPath:      "/userinfo",
	}

	oauth2asServer, err := oauth2as.NewServer(oauth2asConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth2as server: %w", err)
	}

	oidcs := oidcsvr.Server{
		Auth:     auth,
		OAuth2AS: oauth2asServer,
	}

	oidcs.AddHandlers(websvr)

	return websvr, nil
}

func ptr[T any](v T) *T {
	return &v
}
