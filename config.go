package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	Database             string         `json:"database"`
	EncryptionKey        string         `json:"encryptionKey"`
	PrevEncryptionKey    []string       `json:"previousEncryptionKeys"`
	OIDCMaxAge           time.Duration  `json:"oidcMaxAge"`
	OIDCRotationInterval time.Duration  `json:"oidcRotatationInterval"`
	Issuer               []issuerConfig `json:"issuers"`
}

type issuerConfig struct {
	URL    *url.URL       `json:"-"`
	RawURL string         `json:"url"`
	Client []clientConfig `json:"clients"`
}

type clientConfig struct {
	ClientID     string   `json:"clientID"`
	ClientSecret []string `json:"clientSecrets"`
	RedirectURL  []string `json:"redirectURLs"`
	Public       bool     `json:"public"`
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
	if cfg.EncryptionKey == "" {
		return errors.New("required field missing: encryptionKey")
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
		for ii, c := range cfg.Issuer[i].Client {
			if c.ClientID == "" {
				return fmt.Errorf("issuer %s client %d must set clientID", parsed, ii)
			}
			if len(c.ClientSecret) == 0 {
				return fmt.Errorf("issuer %s client %d must set at least one clientSecrets", parsed, ii)
			}
			if len(c.RedirectURL) == 0 {
				return fmt.Errorf("issuer %s client %d must set at least one redirectURLs", parsed, ii)
			}
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
