package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/oklog/run"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("No IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("Non 200 Response found")
)

type cliFlags struct {
	addr   string
	config string

	securePassphrase      string
	prevSecurePassphrases string

	dbPath string
}

func (f *cliFlags) validate() error {
	return nil
}

func main() {
	ctx := context.Background()
	logger, _ := zap.NewProduction()
	l := logrus.New()
	defer logger.Sync() // flushes buffer, if any
	sugar := logger.Sugar()

	// this is optional, ignore when it doesn't exist
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		l.WithError(err).Fatal("Error loading .env file")
	}

	var flags cliFlags

	flag.StringVar(&flags.addr, "addr", getEnvOrDefaultStr("PORT", "127.0.0.1:8080"), "address to listen on, if only port is specific address is assumed to be 0.0.0.0")
	flag.StringVar(&flags.securePassphrase, "secure-passphrase", os.Getenv("SECURE_PASSPHRASE"), "Passphrase for DB encryption")
	flag.StringVar(&flags.prevSecurePassphrases, "prev-secure-passphrase", os.Getenv("SECURE_PASSPHRASES_PREV"), "Previous passphrases for DB encryption, for rotation. Comma-delimited")
	flag.StringVar(&flags.dbPath, "db-path", getEnvOrDefaultStr("DB_PATH", "db/idp.db"), "Path to database file")

	flag.Parse()
	if err := flags.validate(); err != nil {
		l.WithError(err).Fatal("Invalid options")
	}

	if !strings.Contains(flags.addr, ":") {
		flags.addr = net.JoinHostPort("0.0.0.0", flags.addr)
	}
	if flags.securePassphrase == "" {
		sugar.Fatal("secure-passphrase must be provided")
	}

	st, err := newStorage(ctx, l, fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", flags.dbPath))
	if err != nil {
		l.WithError(err).Fatal("failed to create storage")
	}

	_ = st

	/*

		sess, err := session.NewSession(&aws.Config{})
		if err != nil {
			log.Fatalf("creating aws sdk session: %v", err)
		}

		cfgurl, err := url.Parse(flags.config)
		if err != nil {
			sugar.Fatalf("parsing config URL %s: %v", flags.config, err)
		}
		if cfgurl.Scheme != "s3" {
			sugar.Fatalf("%s not a supported config scheme, must be s3", cfgurl.Scheme)
		}

		s3cfg := aws.NewConfig()
		// s3cfg.S3ForcePathStyle = &flags.s3ConfigForcePathStyle
		// if flags.s3ConfigEndpoint != "" {
		// 	s3cfg.Endpoint = &flags.s3ConfigEndpoint
		// }
		cfg, err := newConfigFromS3(ctx, s3.New(sess, s3cfg), cfgurl, sess)
		if err != nil {
			sugar.Fatalf("loading config from %s: %v", flags.config, err)
		}
		cfg.OverrideFromFlags(flags)
		if err := cfg.Validate(); err != nil {
			sugar.Fatalf("invalid config: %v", err)
		}

		krdr := hkdf.New(sha256.New, []byte(flags.securePassphrase), nil, nil)
		scHashKey := make([]byte, 64)
		scEncryptKey := make([]byte, 32)
		csrfKey := make([]byte, 32)
		if _, err := io.ReadFull(krdr, scHashKey); err != nil {
			sugar.Fatal(err)
		}
		if _, err := io.ReadFull(krdr, scEncryptKey); err != nil {
			sugar.Fatal(err)
		}
		if _, err := io.ReadFull(krdr, csrfKey); err != nil {
			sugar.Fatal(err)
		}
		csrfh := csrf.Protect(csrfKey)

		jwts, jwtks, err := cfg.OIDCJWTSigner(ctx)
		if err != nil {
			sugar.Fatalf("getting OIDC JWT signer: %v", err)
		}

		// st, err := cfg.GetStorage()
		// if err != nil {
		// 	sugar.Fatalf("getting storage: %v", err)
		// }

		cfgClients, err := cfg.Clients()
		if err != nil {
			sugar.Fatalf("getting clients: %v", err)
		}
		clients := &multiClients{
			sources: []core.ClientSource{cfgClients},
		}

		ucp, err := cfg.UpstreamClaimsPolicy()
		if err != nil {
			sugar.Fatalf("getting upstream claims policy: %v", err)
		}

		oidcmd := discovery.ProviderMetadata{
			Issuer:                cfg.Issuer,
			JWKSURI:               cfg.Issuer + "/keys",
			AuthorizationEndpoint: cfg.Issuer + "/auth",
			TokenEndpoint:         cfg.Issuer + "/token",
		}
		keysh := discovery.NewKeysHandler(jwtks, 1*time.Hour)
		discoh, err := discovery.NewConfigurationHandler(&oidcmd, discovery.WithCoreDefaults())
		if err != nil {
			log.Fatalf("configuring metadata handler: %v", err)
		}

		oidcsvr, err := core.New(&core.Config{
			AuthValidityTime: 5 * time.Minute,
			CodeValidityTime: 5 * time.Minute,
		}, st, clients, jwts)
		if err != nil {
			log.Fatalf("Failed to create OIDC server instance: %v", err)
		}

		mux := http.NewServeMux()

		mux.Handle("/keys", keysh)
		mux.Handle("/.well-known/openid-configuration", discoh)

		heh := &httpErrHandler{}

		providers := []Provider{}

		// TODO - this probably belongs as a config thi
		for _, p := range cfg.Providers {
			switch p.Type {
			case "oidc":
				oidccli, err := oidc.DiscoverClient(ctx,
					p.OIDC.Issuer, p.OIDC.ClientID, p.OIDC.ClientSecret, cfg.Issuer+"/provider/"+p.ID()+"/callback",
					oidc.WithAdditionalScopes([]string{"profile", "email"}),
				)
				if err != nil {
					log.Fatalf("oidc discovery on %s: %v", p.OIDC.Issuer, err)
				}
				asm := &authSessionManager{
					storage: st,
					oidcsvr: oidcsvr,
					eh:      heh,
				}
				pi := &OIDCProvider{
					name:    p.Name,
					oidccli: oidccli,
					asm:     asm,
					up:      cfg,
					eh:      heh,
				}
				ap := p
				ap.embedProvider = pi
				asm.provider = &ap // TODO - reason about this circular dependency
				providers = append(providers, &ap)
				p := "/provider/" + p.ID()
				mux.Handle(p, http.StripPrefix(p, pi))
				mux.Handle(p+"/", http.StripPrefix(p, pi))
			case "webauthn":
				// TODO - configure a provider when we have one. And when we decide
				// if the manager is one, or if it's independent.

				issParsed, err := url.Parse(cfg.Issuer)
				if err != nil {
					sugar.Fatalf("parsing %s: %v", cfg.Issuer, err)
				}
				sp := strings.Split(issParsed.Host, ":")
				issHost := sp[0]
				// TODO - usernameless via resident keys would be nice, but need to
				// see what support is like.
				rrk := false
				wn, err := webauthn.New(&webauthn.Config{
					RPDisplayName: issHost,    // Display Name for your site
					RPID:          issHost,    // Generally the FQDN for your site
					RPOrigin:      cfg.Issuer, // The origin URL for WebAuthn requests
					AuthenticatorSelection: protocol.AuthenticatorSelection{
						UserVerification:   protocol.VerificationRequired,
						RequireResidentKey: &rrk,
					},
				})
				if err != nil {
					sugar.Fatalf("configuring webauthn: %v", err)
				}

				prefix := "/webauthn"
				mgr := &webauthnManager{
					store:      st,
					webauthn:   wn,
					httpPrefix: prefix,
					// TODO - this needs a prefix
					oidcMiddleware: &oidcm.Handler{
						Issuer:       cfg.Issuer,
						ClientID:     p.Webauthn.ClientID,
						ClientSecret: p.Webauthn.ClientSecret,
						BaseURL:      cfg.Issuer + prefix,
						// Prefix:       prefix,
						RedirectURL:  cfg.Issuer + prefix + "/oidc-callback",
						SessionStore: sessions.NewCookieStore(scHashKey, scEncryptKey),
						SessionName:  "webauthn-manager",
					},
					csrfMiddleware: csrfh,
					admins:         p.Webauthn.AdminSubjects, // TODO - google account id
					acrs:           nil,
				}
				if p.ACR() != "" {
					mgr.oidcMiddleware.ACRValues = []string{p.ACR()}
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

				asm := &authSessionManager{
					storage: st,
					oidcsvr: oidcsvr,
					eh:      heh,
				}
				pi := &webauthnProvider{
					logger:     sugar,
					name:       p.Name,
					store:      st,
					asm:        asm,
					webauthn:   wn,
					httpPrefix: "/provider/" + p.ID(),
				}
				ap := p
				ap.embedProvider = pi
				asm.provider = &ap // TODO - reason about this circular dependency
				providers = append(providers, &ap)
				p := "/provider/" + p.ID()
				mux.Handle(p, http.StripPrefix(p, pi))
				mux.Handle(p+"/", http.StripPrefix(p, pi))
			}
		}

		// server needs one just to retrieve authentcation from the store.
		//
		// TODO - rethink the relationshit between asm / provider / store.
		asm := &authSessionManager{
			storage: st,
		}
		svr := oidcServer{
			issuer:          cfg.Issuer,
			oidcsvr:         oidcsvr,
			providers:       providers,
			asm:             asm,
			eh:              heh,
			tokenValidFor:   15 * time.Minute,
			refreshValidFor: 12 * time.Hour,
			upstreamPolicy:  []byte(ucp),
		}

		svr.AddHandlers(mux)
	*/

	var g run.Group

	/*

		g.Add(run.SignalHandler(ctx, os.Interrupt))

		hh := baseMiddleware(mux, sugar, scHashKey, scEncryptKey)

		hs := &http.Server{
			Addr:    flags.addr,
			Handler: hh,
		}
		g.Add(func() error {
			sugar.Infof("Listing on %s", flags.addr)
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
	*/

	if err := g.Run(); err != nil {
		sugar.Fatal(err)
	}
}

func mustDecodeKey(s string) *rsa.PrivateKey {
	var r *rsa.PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("un-base64 key: %v", err)
	}
	buf := bytes.Buffer{}
	buf.Write(b)
	if err := gob.NewDecoder(&buf).Decode(&r); err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	return r
}

var localDevKey = mustDecodeKey("S/+BAwEBClByaXZhdGVLZXkB/4IAAQQBCVB1YmxpY0tleQH/hAABAUQB/4YAAQZQcmltZXMB/4gAAQtQcmVjb21wdXRlZAH/igAAACT/gwMBAQlQdWJsaWNLZXkB/4QAAQIBAU4B/4YAAQFFAQQAAAAK/4UFAQL/kAAAABn/hwIBAQpbXSpiaWcuSW50Af+IAAH/hgAASP+JAwEBEVByZWNvbXB1dGVkVmFsdWVzAf+KAAEEAQJEcAH/hgABAkRxAf+GAAEEUWludgH/hgABCUNSVFZhbHVlcwH/jgAAAB3/jQIBAQ5bXXJzYS5DUlRWYWx1ZQH/jgAB/4wAADH/iwMBAQhDUlRWYWx1ZQH/jAABAwEDRXhwAf+GAAEFQ29lZmYB/4YAAQFSAf+GAAAA/gFB/4IBAUEC6ucB8ZXiGQZmcUaBfbEOGfYZoPcs32XGIgHCugePcP3G7cIc5DxofX0gV5lo11+DLDFVYmVDTq+YNYrPcr6LHQH9AgACAAFBAkChrvc5tiwMhsNEEvzyal7aR9LyL3aIGivhMCLfUahUpBlsA0C4DkqqcOTzKZI1dDIibFOTgEncrRPzDWikCkEBAiEC+8WMHSJDcR+Mw/I/bsslFBjMZYkJ7j8ph8MrBmqtfp8hAu7Y7vKhGiT8Xek9Foifb7k/I/5NNOOFr4jUDCyVyejDAQEhAucjVxywBgZmlo6VaVLHwQSQN6XHh4xoBDKVJHzBlwG1ASEC0NeuV0i2a5CfLMnVYjDGp9ulxT4M+MRz79g5rOJsYbEBIQIR0UGs8sDAlPOVpuFq3dFa0PROE4YBEQuqe4Rdb+UwpgAA")

func getEnvOrDefaultStr(key, dfault string) string {
	r := os.Getenv(key)
	if r == "" {
		return dfault
	}
	return r
}

func getEnvOrDefaultBool(key string, dfault bool) bool {
	r := os.Getenv(key)
	if r == "" {
		return dfault
	}
	v, err := strconv.ParseBool(r)
	if err != nil {
		return false
	}
	return v
}
