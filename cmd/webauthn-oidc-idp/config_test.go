package main

import (
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lstoll/webauthn-oidc-idp/internal/clients"
)

func TestLoadConfig(t *testing.T) {
	wantCfg := &config{
		Tenants: []*configTenant{
			{
				Issuer:           "https://localhost",
				DBPath:           "db/test.db",
				ImportConfigPath: "testdata/legacyConfig.json",
				Clients: &clients.StaticClients{
					Clients: []clients.Client{
						{
							ID:                 "client-id",
							Secrets:            []string{"client-secret"},
							RedirectURLs:       []string{"http://localhost:8084/callback"},
							SkipPKCE:           true, // Private client: PKCE not required
							UseOverrideSubject: true,
							UseRS256:           true,
						},
						{
							ID:                 "cli",
							Public:             true,
							SkipPKCE:           false, // Public client: PKCE required
							UseOverrideSubject: true,
							UseRS256:           true,
						},
						{
							ID:                 "public-localhost",
							Public:             true,
							SkipPKCE:           false,                                 // Public client: PKCE required
							RedirectURLs:       []string{"http://127.0.0.1/callback"}, // Added due to PermitLocalhostRedirect
							UseOverrideSubject: true,
							UseRS256:           true,
						},
						{
							ID:                 "public-localhost-existing",
							Public:             true,
							SkipPKCE:           false,                                                                 // Public client: PKCE required
							RedirectURLs:       []string{"http://127.0.0.1/callback", "https://example.com/callback"}, // Existing localhost not duplicated
							UseOverrideSubject: true,
							UseRS256:           true,
						},
						{
							ID:                 "explicit-pkce",
							Public:             true,
							SkipPKCE:           true, // Explicitly set to false, so SkipPKCE = !false = true
							UseOverrideSubject: true,
							UseRS256:           true,
						},
						{
							ID:                 "explicit-pkce-true",
							Public:             false,
							SkipPKCE:           false, // Explicitly set to true, so SkipPKCE = !true = false
							RedirectURLs:       []string{"https://example.com/callback"},
							UseOverrideSubject: true,
							UseRS256:           true,
						},
					},
				},
				issuerURL: &url.URL{
					Scheme: "https",
					Host:   "localhost",
				},
			},
		},
	}

	b, err := os.ReadFile("testdata/config.json")
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	cfg, err := loadConfig(b)
	if err != nil {
		t.Fatalf("load config file: %v", err)
	}

	if diff := cmp.Diff(wantCfg, cfg, cmp.AllowUnexported(configTenant{})); diff != "" {
		t.Fatalf("config mismatch (-want +got):\n%s", diff)
	}
}
