package clients

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lstoll/oauth2ext/oidcclientreg"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	_ "github.com/mattn/go-sqlite3"
)

func TestMultiClientsIntegration(t *testing.T) {
	// This test demonstrates how MultiClients integrates both static and dynamic clients
	// and shows the precedence behavior

	// Create static clients
	staticClients := &StaticClients{
		Clients: []Client{
			{
				ID:           "static-web-client",
				RedirectURLs: []string{"https://static.example.com/callback"},
				Secrets:      []string{"static-secret"},
				Public:       false,
				UseRS256:     true,
			},
			{
				ID:           "static-public-client",
				RedirectURLs: []string{"https://static.example.com/public-callback"},
				Secrets:      []string{},
				Public:       true,
			},
		},
	}

	// Create database and dynamic clients
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://dynamic.example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               "dc.dynamic-web-client",
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
		t.Fatalf("failed to create dynamic client: %v", err)
	}

	// Create MultiClients
	multi := NewMultiClients(staticClients, dynamicClients)

	// Test 1: Static client takes precedence over dynamic client with same ID
	// (This would be a real-world scenario where someone tries to register a client
	// with an ID that conflicts with a static client)

	// First, create a dynamic client with the same ID as a static client
	conflictReq := oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://conflict.example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}

	conflictReqBody, err := json.Marshal(conflictReq)
	if err != nil {
		t.Fatalf("failed to marshal conflict request: %v", err)
	}

	conflictParams := queries.CreateDynamicClientParams{
		ID:               "static-web-client", // Same ID as static client
		ClientSecretHash: "conflict-hash",
		RegistrationBlob: string(conflictReqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), conflictParams); err != nil {
		t.Fatalf("failed to create conflict dynamic client: %v", err)
	}

	// Now test that static client takes precedence
	client, found := multi.GetClient("static-web-client")
	if !found {
		t.Fatal("expected to find static client")
	}
	if client.ID != "static-web-client" {
		t.Errorf("expected static client, got %s", client.ID)
	}
	if len(client.RedirectURLs) != 1 || client.RedirectURLs[0] != "https://static.example.com/callback" {
		t.Errorf("expected static client redirect URLs, got %v", client.RedirectURLs)
	}

	// Test 2: Dynamic client works when static client doesn't exist
	client, found = multi.GetClient("dc.dynamic-web-client")
	if !found {
		t.Fatal("expected to find dynamic client")
	}
	if client.ID != "dc.dynamic-web-client" {
		t.Errorf("expected dynamic client, got %s", client.ID)
	}

	// Test 3: Client validation works for both types
	valid, err := multi.IsValidClientID(context.Background(), "static-web-client")
	if err != nil || !valid {
		t.Error("expected static client to be valid")
	}

	valid, err = multi.IsValidClientID(context.Background(), "dc.dynamic-web-client")
	if err != nil || !valid {
		t.Error("expected dynamic client to be valid")
	}

	// Test 4: Client secret validation works for both types
	valid, err = multi.ValidateClientSecret(context.Background(), "static-web-client", "static-secret")
	if err != nil || !valid {
		t.Error("expected static client secret to be valid")
	}

	// Test 5: Redirect URIs work for both types
	uris, err := multi.RedirectURIs(context.Background(), "static-web-client")
	if err != nil || len(uris) != 1 || uris[0] != "https://static.example.com/callback" {
		t.Errorf("expected static client redirect URIs, got %v, err: %v", uris, err)
	}

	uris, err = multi.RedirectURIs(context.Background(), "dc.dynamic-web-client")
	if err != nil || len(uris) != 1 || uris[0] != "https://dynamic.example.com/callback" {
		t.Errorf("expected dynamic client redirect URIs, got %v, err: %v", uris, err)
	}

	// Test 6: Client options work for both types
	opts, err := multi.ClientOpts(context.Background(), "static-web-client")
	if err != nil || len(opts) == 0 {
		t.Errorf("expected static client to have options, got %d, err: %v", len(opts), err)
	}

	opts, err = multi.ClientOpts(context.Background(), "dc.dynamic-web-client")
	if err != nil || len(opts) == 0 {
		t.Errorf("expected dynamic client to have options, got %d, err: %v", len(opts), err)
	}

	// Test 7: Public client handling
	client, found = multi.GetClient("static-public-client")
	if !found {
		t.Fatal("expected to find public static client")
	}
	if !client.Public {
		t.Error("expected client to be public")
	}

	// Test 8: Non-existent client handling
	_, found = multi.GetClient("nonexistent")
	if found {
		t.Error("expected not to find nonexistent client")
	}

	valid, err = multi.IsValidClientID(context.Background(), "nonexistent")
	if err != nil || valid {
		t.Error("expected nonexistent client to be invalid")
	}
}
