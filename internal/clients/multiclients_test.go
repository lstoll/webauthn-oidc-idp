package clients

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

func TestMultiClients_GetClient(t *testing.T) {
	// Test static client takes precedence
	staticClients := &StaticClients{
		Clients: []Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"secret1"},
				Public:       false,
			},
		},
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client with the same ID
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://dynamic.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "static-client", // Same ID as static client
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	multi := NewMultiClients(staticClients, dynamicClients)

	// Should get static client (takes precedence)
	client, found := multi.GetClient("static-client")
	if !found {
		t.Error("expected to find client")
	}
	if client.ID != "static-client" {
		t.Errorf("expected static client, got %s", client.ID)
	}
	if len(client.RedirectURLs) != 1 || client.RedirectURLs[0] != "https://example.com/callback" {
		t.Errorf("expected static client redirect URLs, got %v", client.RedirectURLs)
	}

	// Test dynamic client when static doesn't exist
	_, found = multi.GetClient("dc.dynamic-only")
	if found {
		t.Error("expected not to find dynamic client with dc. prefix")
	}

	// Test non-existent client
	_, found = multi.GetClient("nonexistent")
	if found {
		t.Error("expected not to find nonexistent client")
	}
}

func TestMultiClients_IsValidClientID(t *testing.T) {
	staticClients := &StaticClients{
		Clients: []Client{
			{ID: "static-client"},
		},
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "dc.dynamic-client",
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	multi := NewMultiClients(staticClients, dynamicClients)

	// Test static client
	valid, err := multi.IsValidClientID(context.Background(), "static-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected static client to be valid")
	}

	// Test dynamic client
	valid, err = multi.IsValidClientID(context.Background(), "dc.dynamic-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected dynamic client to be valid")
	}

	// Test non-existent client
	valid, err = multi.IsValidClientID(context.Background(), "nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected nonexistent client to be invalid")
	}
}

func TestMultiClients_ValidateClientSecret(t *testing.T) {
	staticClients := &StaticClients{
		Clients: []Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"static-secret"},
				Public:       false,
			},
		},
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "dc.dynamic-client",
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	multi := NewMultiClients(staticClients, dynamicClients)

	// Test static client secret
	valid, err := multi.ValidateClientSecret(context.Background(), "static-client", "static-secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected static client secret to be valid")
	}

	// Test static client with wrong secret
	valid, err = multi.ValidateClientSecret(context.Background(), "static-client", "wrong-secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected wrong static client secret to be invalid")
	}

	// Test dynamic client secret (this will fail since we don't have the actual secret)
	// But it should not error
	valid, err = multi.ValidateClientSecret(context.Background(), "dc.dynamic-client", "any-secret")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected dynamic client secret to be invalid with wrong secret")
	}
}

func TestMultiClients_RedirectURIs(t *testing.T) {
	staticClients := &StaticClients{
		Clients: []Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://static.com/callback"},
				Secrets:      []string{"secret1"},
				Public:       false,
			},
		},
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://dynamic.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "dc.dynamic-client",
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	multi := NewMultiClients(staticClients, dynamicClients)

	// Test static client redirect URIs
	uris, err := multi.RedirectURIs(context.Background(), "static-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(uris) != 1 || uris[0] != "https://static.com/callback" {
		t.Errorf("expected static client redirect URIs, got %v", uris)
	}

	// Test dynamic client redirect URIs
	uris, err = multi.RedirectURIs(context.Background(), "dc.dynamic-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(uris) != 1 || uris[0] != "https://dynamic.com/callback" {
		t.Errorf("expected dynamic client redirect URIs, got %v", uris)
	}

	// Test non-existent client
	_, err = multi.RedirectURIs(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent client")
	}
}

func TestMultiClients_ClientOpts(t *testing.T) {
	staticClients := &StaticClients{
		Clients: []Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"secret1"},
				Public:       false,
				UseRS256:     true, // This should create a signing alg option
			},
		},
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "dc.dynamic-client",
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	multi := NewMultiClients(staticClients, dynamicClients)

	// Test static client options
	opts, err := multi.ClientOpts(context.Background(), "static-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("expected static client to have options")
	}

	// Test dynamic client options
	opts, err = multi.ClientOpts(context.Background(), "dc.dynamic-client")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("expected dynamic client to have options")
	}

	// Test non-existent client
	opts, err = multi.ClientOpts(context.Background(), "nonexistent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("expected no options for nonexistent client, got %d", len(opts))
	}
}
