package clients

import (
	"context"
	"testing"

	"lds.li/passidp/internal/config"
)

func TestStaticClients_ClientOptsPublic(t *testing.T) {
	sc := &StaticClients{
		Clients: []config.Client{
			{
				ID:           "public-client",
				RedirectURLs: []string{"http://127.0.0.1/callback"},
				Public:       true,
			},
			{
				ID:           "confidential-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"secret"},
			},
		},
	}

	publicOpts, err := sc.ClientOpts(context.Background(), "public-client")
	if err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
	if len(publicOpts) != 2 {
		t.Fatalf("expected public + signing alg options, got %d", len(publicOpts))
	}

	confOpts, err := sc.ClientOpts(context.Background(), "confidential-client")
	if err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
	if len(confOpts) != 1 {
		t.Fatalf("expected signing alg option only, got %d", len(confOpts))
	}
}

func TestConfigValidatePublicSkipPKCE(t *testing.T) {
	cfg := &config.Config{
		Issuer: "https://idp.example.com",
		Clients: []config.Client{{
			ID:           "bad",
			RedirectURLs: []string{"http://127.0.0.1/callback"},
			Public:       true,
			SkipPKCE:     true,
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for public client with skipPKCE")
	}
}

func TestStaticClientsAcceptRS256(t *testing.T) {
	sc := &StaticClients{Clients: []config.Client{{ID: "rsa-client", UseRS256: true}}}
	if _, err := sc.ClientOpts(context.Background(), "rsa-client"); err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
}
