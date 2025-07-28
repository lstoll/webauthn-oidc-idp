package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/lstoll/webauthn-oidc-idp/internal/clients"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
	"github.com/tailscale/hujson"
)

// legacyConfig is the config format for the previous era of IDP. Used to import
// clients.
type legacyConfig struct {
	// Database is unused.
	Database string `json:"database"`
	Issuers  []struct {
		URL     string        `json:"url"`
		Clients legacyClients `json:"clients"`
	} `json:"issuers"`
}

type legacyClients []legacyClient

// legacyClient matches the old client format.
//
// ref: https://github.com/lstoll/oauth2ext/blob/989e22bde1f1b12721bf21f7ab50a351ba115da3/core/staticclients/staticclients.go#L58-L80
type legacyClient struct {
	// ID is the identifier for this client, corresponds to the client ID.
	ID string `json:"id" yaml:"id"`
	// Secrets is a list of valid client secrets for this client. At least
	// one secret is required, unless the client is Public and uses PKCE.
	Secrets []string `json:"clientSecrets" yaml:"clientSecrets"`
	// RedirectURLS is a list of valid redirect URLs for this client. At least
	// one is required, unless the client is public a PermitLocalhostRedirect is
	// true. These are an exact match
	RedirectURLs []string `json:"redirectURLs" yaml:"redirectURLs"`
	// Public indicates that this client is public. A "public" client is one who
	// can't keep their credentials confidential.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
	Public bool `json:"public" yaml:"public"`
	// PermitLocalhostRedirect allows redirects to localhost, if this is a
	// public client
	PermitLocalhostRedirect bool `json:"permitLocalhostRedirect" yaml:"permitLocalhostRedirect"`
	// RequiresPKCE indicates that this client should be required to use PKCE
	// for the token exchange. This defaults to true for public clients, and
	// false for non-public clients.
	RequiresPKCE *bool `json:"requiresPKCE" yaml:"requiresPKCE"`
}

type config struct {
	// Tenants is the list of tenants to serve.
	Tenants []*configTenant `json:"tenants"`
}

type configTenant struct {
	// Issuer URL for the tenant.
	Issuer string `json:"issuer"`
	// DBPath is the path to the SQLite database file for the tenant.
	DBPath string `json:"dbPath"`
	// ImportDBPath is a path to a database file for the previous era of IDP,
	// the jsonfile. It is currently still partially used, and must be provided.
	ImportDBPath string `json:"importDBPath"`
	// ImportConfigPath is a path to a config file for the previous era of IDP.
	// It will import the clients from that config. (not yet, they are just
	// used.). It is currently still required for the client config.
	ImportConfigPath string `json:"importConfigPath"`
	// StaticClientsPath is a path to a list of static clients
	StaticClientsPath string `json:"staticClientsPath"`

	// ImportedClients is the clients imported from the legacy config, filled at
	// parse time, and merged with the static clients.
	Clients *clients.StaticClients `json:"-"`
	// db connection for the tenant.
	db *sql.DB `json:"-"`
	// legacyDB is the database connection for the legacy config
	legacyDB *idp.DB `json:"-"`
	// issuerURL is the parsed URL of the issuer.
	issuerURL *url.URL `json:"-"`
}

func loadConfig(file []byte) (*config, error) {
	cfg := &config{}

	cfgb := []byte(os.Expand(string(file), getenvWithDefault))
	cfgb, err := hujson.Standardize(cfgb)
	if err != nil {
		return nil, fmt.Errorf("standardize config: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(cfgb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if len(cfg.Tenants) != 1 {
		return nil, errors.New("must configure exactly 1 tenant")
	}
	var seenHostnames []string
	for i, tenant := range cfg.Tenants {
		if tenant.Issuer == "" {
			return nil, fmt.Errorf("tenant %d missing issuer", i)
		}
		issuerURL, err := url.Parse(tenant.Issuer)
		if err != nil {
			return nil, fmt.Errorf("parse issuer host %s: %w", tenant.Issuer, err)
		}
		cfg.Tenants[i].issuerURL = issuerURL

		if slices.Contains(seenHostnames, issuerURL.Hostname()) {
			return nil, fmt.Errorf("tenant %s duplicate issuer hostname %s", tenant.Issuer, issuerURL.Hostname())
		}
		seenHostnames = append(seenHostnames, issuerURL.Hostname())
		if tenant.DBPath == "" {
			return nil, fmt.Errorf("tenant %s missing dbPath", tenant.Issuer)
		}

		if tenant.ImportConfigPath == "" {
			return nil, fmt.Errorf("tenant %s missing importConfigPath", tenant.Issuer)
		}

		legacyCfgB, err := os.ReadFile(tenant.ImportConfigPath)
		if err != nil {
			return nil, fmt.Errorf("tenant %s read importConfigPath: %w", tenant.Issuer, err)
		}
		var legacyCfg legacyConfig
		dec := json.NewDecoder(strings.NewReader(os.Expand(string(legacyCfgB), getenvWithDefault)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&legacyCfg); err != nil {
			return nil, fmt.Errorf("tenant %s unmarshal importConfigPath: %w", tenant.Issuer, err)
		}
		if len(legacyCfg.Issuers) != 1 {
			return nil, fmt.Errorf("tenant %s must configure exactly 1 issuer", tenant.Issuer)
		}

		var validErr error
		// Convert legacy clients to new format
		var newClients []clients.Client
		for ii, c := range legacyCfg.Issuers[0].Clients {
			if c.ID == "" {
				validErr = errors.Join(validErr, fmt.Errorf("tenant %s client %d must set clientID", tenant.Issuer, ii))
			}
			if len(c.RedirectURLs) == 0 && !c.Public {
				validErr = errors.Join(validErr, fmt.Errorf("tenant %s client %d requires a redirect URL when not public with localhost permitted", tenant.Issuer, ii))
			}

			// Build the new client format
			cl := clients.Client{
				ID:           c.ID,
				Secrets:      c.Secrets,
				RedirectURLs: c.RedirectURLs,
				Public:       c.Public,
				// We always expected these to use the override subject, opt-in
				// by default here, the new config can change that behaviour.
				UseOverrideSubject: true,
			}

			// Handle PKCE logic: SkipPKCE is inverted from RequiresPKCE
			if c.RequiresPKCE != nil {
				cl.SkipPKCE = !*c.RequiresPKCE
			} else {
				// Default behavior: PKCE required for public clients, not for private clients
				cl.SkipPKCE = !c.Public
			}

			// Handle localhost redirect for public clients with PermitLocalhostRedirect
			if c.Public && c.PermitLocalhostRedirect {
				// Add localhost callback if not already present
				hasLocalhost := slices.Contains(cl.RedirectURLs, "http://127.0.0.1/callback")
				if !hasLocalhost {
					cl.RedirectURLs = append(cl.RedirectURLs, "http://127.0.0.1/callback")
				}
			}

			newClients = append(newClients, cl)
		}
		if validErr != nil {
			return nil, validErr
		}

		cfg.Tenants[i].Clients = &clients.StaticClients{Clients: newClients}

		if cfg.Tenants[i].StaticClientsPath != "" {
			scb, err := os.ReadFile(cfg.Tenants[i].StaticClientsPath)
			if err != nil {
				return nil, fmt.Errorf("tenant %s read staticClientsPath: %w", tenant.Issuer, err)
			}
			scb = []byte(os.Expand(string(scb), getenvWithDefault))
			scb, err = hujson.Standardize(scb)
			if err != nil {
				return nil, fmt.Errorf("standardize config: %w", err)
			}

			var sc clients.StaticClients
			dec := json.NewDecoder(bytes.NewReader(scb))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&sc); err != nil {
				return nil, fmt.Errorf("decode config: %w", err)
			}

			if err := sc.Validate(); err != nil {
				return nil, fmt.Errorf("tenant %s validate staticClientsPath: %w", tenant.Issuer, err)
			}

			merged, err := clients.MergeStaticClients(cfg.Tenants[i].Clients, &sc)
			if err != nil {
				return nil, fmt.Errorf("tenant %s merge staticClientsPath: %w", tenant.Issuer, err)
			}
			cfg.Tenants[i].Clients = merged
		}

	}
	return cfg, nil
}

// getenvWithDefault maps FOO:-default to $FOO or default if $FOO is unset or
// null.
func getenvWithDefault(key string) string {
	parts := strings.SplitN(key, ":-", 2)
	val := os.Getenv(parts[0])
	if val == "" && len(parts) == 2 {
		val = parts[1]
	}
	return val
}
