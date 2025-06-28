package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/webauthn-oidc-idp/internal/idp"
	"github.com/tailscale/hujson"
)

// legacyConfig is the config format for the previous era of IDP. Used to import
// clients.
type legacyConfig struct {
	// Database is unused.
	Database string `json:"database"`
	Issuers  []struct {
		URL     string                 `json:"url"`
		Clients []staticclients.Client `json:"clients"`
	} `json:"issuers"`
}

type config struct {
	Tenants []*configTenant `json:"tenants"`
}

type configTenant struct {
	// Hostname for the tenant. Issuer will be constructed from this, under
	// HTTPS.
	Hostname string `json:"hostname"`
	// DBPath is the path to the SQLite database file for the tenant.
	DBPath string `json:"dbPath"`
	// ImportDBPath is a path to a database file for the previous era of IDP,
	// the jsonfile. It is currently still partially used, and must be provided.
	ImportDBPath string `json:"importDBPath"`
	// ImportConfigPath is a path to a config file for the previous era of IDP.
	// It will import the clients from that config. (not yet, they are just
	// used.). It is currently still required for the client config.
	ImportConfigPath string `json:"importConfigPath"`

	// ImportedClients is the clients imported from the legacy config, filled at
	// parse time.
	ImportedClients []staticclients.Client `json:"-"`

	// db connection for the tenant.
	db *sql.DB `json:"-"`
	// legacyDB is the database connection for the legacy config
	legacyDB *idp.DB `json:"-"`
	// issuerURL is the URL of the issuer for the tenant, constructed from the
	// hostname.
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
	for i, tenant := range cfg.Tenants {
		if tenant.Hostname == "" {
			return nil, fmt.Errorf("tenant %d missing hostname", i)
		}
		if tenant.DBPath == "" {
			return nil, fmt.Errorf("tenant %s missing dbPath", tenant.Hostname)
		}

		if tenant.ImportConfigPath == "" {
			return nil, fmt.Errorf("tenant %s missing importConfigPath", tenant.Hostname)
		}

		legacyCfgB, err := os.ReadFile(tenant.ImportConfigPath)
		if err != nil {
			return nil, fmt.Errorf("tenant %s read importConfigPath: %w", tenant.Hostname, err)
		}
		var legacyCfg legacyConfig
		dec := json.NewDecoder(strings.NewReader(os.Expand(string(legacyCfgB), getenvWithDefault)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&legacyCfg); err != nil {
			return nil, fmt.Errorf("tenant %s unmarshal importConfigPath: %w", tenant.Hostname, err)
		}
		if len(legacyCfg.Issuers) != 1 {
			return nil, fmt.Errorf("tenant %s must configure exactly 1 issuer", tenant.Hostname)
		}

		cfg.Tenants[i].ImportedClients = legacyCfg.Issuers[0].Clients

		var validErr error
		for ii, c := range tenant.ImportedClients {
			if c.ID == "" {
				validErr = errors.Join(validErr, fmt.Errorf("tenant %s client %d must set clientID", tenant.Hostname, ii))
			}
			if len(c.RedirectURLs) == 0 && !c.Public && !c.PermitLocalhostRedirect {
				validErr = errors.Join(validErr, fmt.Errorf("tenant %s client %d requires a redirect URL when not public with localhost permitted", tenant.Hostname, ii))
			}
			if len(c.Secrets) == 0 && !c.Public && c.RequiresPKCE != nil && !*c.RequiresPKCE {
				validErr = errors.Join(validErr, fmt.Errorf("tenant %s client %d requires a client secret when PKCE not required", tenant.Hostname, ii))
			}
		}
		if validErr != nil {
			return nil, validErr
		}

		issuerURL, err := url.Parse(fmt.Sprintf("https://%s", tenant.Hostname))
		if err != nil {
			return nil, fmt.Errorf("parse issuer host %s: %w", tenant.Hostname, err)
		}
		cfg.Tenants[i].issuerURL = issuerURL
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
