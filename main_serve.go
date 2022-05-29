package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/oklog/run"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	oidcm "github.com/pardot/oidc/middleware"
	"gopkg.in/alecthomas/kingpin.v2"
)

type serveConfig struct {
	addr string
}

func serveCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *globalCfg) error) {
	serve := app.Command("serve", "Run the IDP as a server")

	issuer := serve.Flag("issuer", "OIDC issuer for this service").Envar("ISSUER").Required().String()
	addr := serve.Flag("addr", "Address to listen on").Envar("ADDR").Default("127.0.0.1:5556").String()
	oidcRotateInterval := serve.Flag("oidc-rotate-interval", "Interval we should rotate out OIDC signing keys").Envar("OIDC_ROTATE_INTERVAL").Default("24h").Duration()
	oidMaxAge := serve.Flag("oidc-max-age", "Maximum age OIDC keys should be considered valid").Envar("OIDC_MAX_AGE").Default("168h").Duration()

	return serve, func(ctx context.Context, gcfg *globalCfg) error {

		encryptor := newEncryptor[[]byte](gcfg.keyset.dbCurr, gcfg.keyset.dbPrev...)

		oidcrotator := &dbRotator[rotatableRSAKey, *rotatableRSAKey]{
			db:  gcfg.storage.db,
			log: ctxLog(ctx),

			usage: rotatorUsageOIDC,

			rotateInterval: *oidcRotateInterval,
			maxAge:         *oidMaxAge,

			newFn: func() (*rotatableRSAKey, error) {
				return newRotatableRSAKey(encryptor)
			},
		}

		sessionrotator := &dbRotator[rotatableSecurecookie, *rotatableSecurecookie]{
			db:  gcfg.storage.db,
			log: ctxLog(ctx),

			usage: rotatorUsageOIDC,

			rotateInterval: *oidcRotateInterval,
			maxAge:         *oidMaxAge,

			newFn: func() (*rotatableSecurecookie, error) {
				return newRotatableSecureCookie(encryptor)
			},
		}
		sessmgr := &secureCookieManager{
			rotator:   sessionrotator,
			encryptor: encryptor,
		}

		oidcSigner := &oidcSigner{
			rotator:   oidcrotator,
			encryptor: encryptor,
		}

		clients := &multiClients{
			// sources: []core.ClientSource{cfgClients}, // TODO - load from file
		}

		oidcmd := discovery.ProviderMetadata{
			Issuer:                *issuer,
			JWKSURI:               *issuer + "/keys",
			AuthorizationEndpoint: *issuer + "/auth",
			TokenEndpoint:         *issuer + "/token",
		}
		keysh := discovery.NewKeysHandler(oidcSigner, 1*time.Hour)
		discoh, err := discovery.NewConfigurationHandler(&oidcmd, discovery.WithCoreDefaults())
		if err != nil {
			log.Fatalf("configuring metadata handler: %v", err)
		}

		oidcsvr, err := core.New(&core.Config{
			AuthValidityTime: 5 * time.Minute,
			CodeValidityTime: 5 * time.Minute,
		}, gcfg.storage, clients, oidcSigner)
		if err != nil {
			log.Fatalf("Failed to create OIDC server instance: %v", err)
		}

		mux := http.NewServeMux()

		mux.Handle("/keys", keysh)
		mux.Handle("/.well-known/openid-configuration", discoh)

		heh := &httpErrHandler{}

		// start webauthn provider-level config
		issParsed, err := url.Parse(*issuer)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", *issuer, err)
		}
		sp := strings.Split(issParsed.Host, ":")
		issHost := sp[0]
		// TODO - usernameless via resident keys would be nice, but need to
		// see what support is like.
		rrk := false
		wn, err := webauthn.New(&webauthn.Config{
			RPDisplayName: issHost, // Display Name for your site
			RPID:          issHost, // Generally the FQDN for your site
			RPOrigin:      *issuer, // The origin URL for WebAuthn requests
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				UserVerification:   protocol.VerificationRequired,
				RequireResidentKey: &rrk,
			},
		})
		if err != nil {
			return fmt.Errorf("configuring webauthn: %w", err)
		}

		// start configuration of webauthn manager

		prefix := "/webauthn"
		mgr := &webauthnManager{
			store:      gcfg.storage,
			webauthn:   wn,
			httpPrefix: prefix,
			// TODO - this needs a prefix
			oidcMiddleware: &oidcm.Handler{
				Issuer:       *issuer,
				ClientID:     uuid.New().String(), // TODO - something that will live beyond restarts
				ClientSecret: uuid.New().String(),
				BaseURL:      *issuer + prefix,
				// Prefix:       prefix, // ????
				RedirectURL:  *issuer + prefix + "/oidc-callback",
				SessionStore: sessmgr,
				SessionName:  "webauthn-manager",
			},
			csrfMiddleware: sessmgr.CSRFHandler(ctx, heh),
			// admins: p.Webauthn.AdminSubjects, // TODO - google account id
			acrs: nil,
		}

		clients.sources = append([]core.ClientSource{
			&staticClients{
				clients: []Client{
					{
						ClientID:      mgr.oidcMiddleware.ClientID,
						ClientSecrets: []string{mgr.oidcMiddleware.ClientSecret},
						RedirectURLs:  []string{mgr.oidcMiddleware.RedirectURL},
					},
				},
			},
		}, clients.sources...)

		mux.HandleFunc(mgr.httpPrefix, func(w http.ResponseWriter, r *http.Request) {
			log.Printf("called")
			http.Redirect(w, r, mgr.httpPrefix+"/", http.StatusMovedPermanently)
		})
		mux.Handle(mgr.httpPrefix+"/", http.StripPrefix(mgr.httpPrefix, mgr))

		svr := oidcServer{
			issuer:          *issuer,
			oidcsvr:         oidcsvr,
			eh:              heh,
			tokenValidFor:   15 * time.Minute,
			refreshValidFor: 12 * time.Hour,
			// upstreamPolicy:  []byte(ucp),
			webauthn: wn,
			store:    gcfg.storage,
			storage:  gcfg.storage,
		}

		svr.AddHandlers(mux)

		var g run.Group

		g.Add(run.SignalHandler(ctx, os.Interrupt))

		hh := baseMiddleware(mux, ctxLog(ctx), sessmgr)

		hs := &http.Server{
			Addr:    *addr,
			Handler: hh,
		}
		g.Add(func() error {
			ctxLog(ctx).Info("Listing on %s", *addr)
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

		return g.Run()
	}
}
