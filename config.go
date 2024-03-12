package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/lstoll/oidc/core/staticclients"
)

type config struct {
	Database string         `json:"database"`
	Issuer   []issuerConfig `json:"issuers"`
}

type issuerConfig struct {
	URL     *url.URL               `json:"-"`
	RawURL  string                 `json:"url"`
	Clients []staticclients.Client `json:"clients"`
}

func loadConfig(file []byte, cfg *config) error {
	dec := json.NewDecoder(strings.NewReader(os.Expand(string(file), getenvWithDefault)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return err
	}
	if cfg.Database == "" {
		return errors.New("required field missing: database")
	}
	if len(cfg.Issuer) != 1 {
		return errors.New("must configure exactly 1 issuer")
	}
	for i := range cfg.Issuer {
		parsed, err := url.Parse(cfg.Issuer[i].RawURL)
		if err != nil {
			return fmt.Errorf("parse issuer url %d: %w", i, err)
		}
		cfg.Issuer[i].URL = parsed
		var validErr error
		for ii, c := range cfg.Issuer[i].Clients {
			if c.ID == "" {
				validErr = errors.Join(validErr, fmt.Errorf("issuer %s client %d must set clientID", parsed, ii))
			}
			if len(c.RedirectURLs) == 0 && !c.Public && !c.PermitLocalhostRedirect {
				validErr = errors.Join(validErr, fmt.Errorf("issuer %s client %d requires a redirect URL when not public with localhost permitted", parsed, ii))
			}
			if len(c.Secrets) == 0 && !c.Public && c.RequiresPKCE != nil && !*c.RequiresPKCE {
				validErr = errors.Join(validErr, fmt.Errorf("issuer %s client %d requires a client secret when PKCE not required", parsed, ii))
			}
		}
		if validErr != nil {
			return validErr
		}
	}
	return nil
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
