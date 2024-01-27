package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/justinas/nosurf"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/discovery"
	oidcm "github.com/lstoll/oidc/middleware"
	"github.com/oklog/run"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

type serveConfig struct {
	addr string
}

//go:embed web/public/*
var staticFiles embed.FS

func serveCommand(app *kingpin.Application) (cmd *kingpin.CmdClause, runner func(context.Context, *globalCfg) error) {
	serve := app.Command("serve", "Run the IDP as a server")

	issuer := serve.Flag("issuer", "OIDC issuer for this service").Envar("ISSUER").Required().String()
	addr := serve.Flag("addr", "Address to listen on").Envar("ADDR").Default("127.0.0.1:8085").String()
	oidcRotateInterval := serve.Flag("oidc-rotate-interval", "Interval we should rotate out OIDC signing keys").Envar("OIDC_ROTATE_INTERVAL").Default("24h").Duration()
	oidMaxAge := serve.Flag("oidc-max-age", "Maximum age OIDC keys should be considered valid").Envar("OIDC_MAX_AGE").Default("168h").Duration()
	serveAutocert := serve.Flag("serve-autocert", "if set, serve using TLS + letsencrypt. If set, implies acceptance of their TOS").Envar("SERVE_AUTOCERT").Default("false").Bool()
	autocertEmail := serve.Flag("autocert-email", "E-mail address to register with letsencrypt.").Envar("AUTOCERT_EMAIL").String()
	autocertAdditionalHosts := serve.Flag("autocert-additional-hosts", "Additional hostnames (aside from the issuer) we should enable cert provisioning for.").Envar("AUTOCERT_ADDITIONAL_HOSTNAMES").Strings()
	clientsFile := serve.Flag("clients", "Path to file containing oauth2/oidc clients config").Envar("CLIENTS_FILE").ExistingFile()

	return serve, func(ctx context.Context, gcfg *globalCfg) error {
		if *serveAutocert && *autocertEmail == "" {
			return errors.New("autocert-email needs to be provided when serving with autocert")
		}

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
		if err := oidcrotator.RotateIfNeeded(ctx); err != nil {
			return err
		}

		oidcSigner := &oidcSigner{
			rotator:   oidcrotator,
			encryptor: encryptor,
		}

		clients := &multiClients{}

		if *clientsFile != "" {
			b, err := os.ReadFile(*clientsFile)
			if err != nil {
				return fmt.Errorf("reading file %s: %v", *clientsFile, err)
			}
			sc := &staticClients{}
			if err := yaml.Unmarshal(b, &sc.clients); err != nil {
				return fmt.Errorf("decoding clients file %s: %w", *clientsFile, err)
			}
			clients.sources = append(clients.sources, sc)
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

		// TODO - sqlite storage
		webSessMgr := scs.New()
		// TODO - wrap the scs session manager for gorilla?
		gorillaSessMgr := sessions.NewCookieStore()

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
		mgr := &webauthnManager{
			store:          gcfg.storage,
			webauthn:       wn,
			sessionManager: webSessMgr,
			oidcMiddleware: &oidcm.Handler{
				Issuer:       *issuer,
				ClientID:     uuid.New().String(), // TODO - something that will live beyond restarts
				ClientSecret: uuid.New().String(),
				BaseURL:      *issuer,
				RedirectURL:  *issuer + "/local-oidc-callback",
				SessionStore: gorillaSessMgr,
				SessionName:  "webauthn-manager",
			},
			csrfMiddleware: nosurf.NewPure,
			// admins: p.Webauthn.AdminSubjects, // TODO - google account id
			acrs: nil,
		}
		// this is a dumb hack, because we use the middleware super
		// restrictively but it needs to catch it's callback.
		mux.Handle("/local-oidc-callback", mgr.oidcMiddleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("should never get here?"))
		})))

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

		mgr.AddHandlers(mux)

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

		pubContent, err := fs.Sub(fs.FS(staticFiles), "web")
		if err != nil {
			return fmt.Errorf("creating public subfs: %w", err)
		}
		fs := http.FileServer(http.FS(pubContent))
		mux.Handle("/public/", fs)

		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			if err := gcfg.storage.db.Ping(); err != nil {
				ctxLog(ctx).WithError(err).Error("failed to ping database in health check")
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
			Addr:    *addr,
			Handler: hh,
		}

		g.Add(func() error {
			if *serveAutocert {
				acc := &autocertStore{
					db:        gcfg.storage.db,
					encryptor: encryptor,
				}
				m := &autocert.Manager{
					Cache:      acc,
					Prompt:     autocert.AcceptTOS,
					Email:      *autocertEmail,
					HostPolicy: autocert.HostWhitelist(append([]string{issHost}, (*autocertAdditionalHosts)...)...),
				}
				hs.TLSConfig = m.TLSConfig()
				ctxLog(ctx).Infof("Listing on https://%s", *addr)
				if err := hs.ListenAndServeTLS("", ""); err != nil {
					return fmt.Errorf("serving http: %v", err)
				}
			} else {
				ctxLog(ctx).Infof("Listing on http://%s", *addr)
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

		rotInt := make(chan struct{}, 1)
		g.Add(func() error {
			ctxLog(ctx).Info("Starting rotator")
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
}
