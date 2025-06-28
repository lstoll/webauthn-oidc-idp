package main

import (
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lstoll/oidc/core/staticclients"
)

func TestLoadConfig(t *testing.T) {
	wantCfg := &config{
		Tenants: []*configTenant{
			{
				Hostname:         "localhost",
				DBPath:           "db/test.db",
				ImportConfigPath: "testdata/legacyConfig.json",
				ImportedClients: []staticclients.Client{
					{
						ID:           "client-id",
						Secrets:      []string{"client-secret"},
						RedirectURLs: []string{"http://localhost:8084/callback"},
					},
					{
						ID:                      "cli",
						Public:                  true,
						PermitLocalhostRedirect: true,
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
