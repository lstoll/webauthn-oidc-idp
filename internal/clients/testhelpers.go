package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/passidp/internal/storage"
)

func setupTestDB(t *testing.T) *storage.DynamicClientStore {
	t.Helper()
	return storage.NewDynamicClientStore(storage.OpenTest(t))
}

// createTestDynamicClient creates a dynamic client in the database for testing
func createTestDynamicClient(t *testing.T, db *storage.DynamicClientStore, clientID string, req oidcclientreg.ClientRegistrationRequest) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	testSecret := fmt.Sprintf("test-secret-%s", clientID)

	if err := db.CreateDynamicClient(context.Background(), clientID, testSecret, string(reqBody), time.Now().AddDate(0, 0, 14)); err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}
}

// defaultTestClientRequest returns a standard test client registration request
func defaultTestClientRequest() oidcclientreg.ClientRegistrationRequest {
	return oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
		ClientName:      "Test Client",
	}
}
