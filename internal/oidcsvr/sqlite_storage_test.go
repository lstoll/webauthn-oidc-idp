package oidcsvr

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as"
	dbpkg "github.com/lstoll/webauthn-oidc-idp/db"
	_ "github.com/mattn/go-sqlite3"
)

func TestSQLiteStorage(t *testing.T) {
	// Create an in-memory SQLite database for testing
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := dbpkg.Migrate(t.Context(), db); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	storage := NewSQLiteStorage(db)

	// Test creating a grant
	grantID := uuid.New()
	authCode := "test_auth_code"
	refreshToken := "test_refresh_token"
	expiresAt := time.Now().Add(time.Hour)

	grant := &oauth2as.StoredGrant{
		ID:            grantID,
		UserID:        "test_user",
		ClientID:      "test_client",
		GrantedScopes: []string{"openid", "profile"},
		AuthCode:      &authCode,
		RefreshToken:  &refreshToken,
		Request: &oauth2as.AuthRequest{
			ClientID: "test_client",
			Scopes:   []string{"openid", "profile"},
		},
		ExpiresAt: expiresAt,
	}

	if err := storage.CreateGrant(context.Background(), grant); err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}

	// Test retrieving by ID
	retrieved, err := storage.GetGrant(context.Background(), grantID)
	if err != nil {
		t.Fatalf("failed to get grant: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected grant to be found")
	}
	if retrieved.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrieved.ID)
	}
	if *retrieved.AuthCode != authCode {
		t.Errorf("expected auth code %s, got %s", authCode, *retrieved.AuthCode)
	}
	if *retrieved.RefreshToken != refreshToken {
		t.Errorf("expected refresh token %s, got %s", refreshToken, *retrieved.RefreshToken)
	}

	// Test retrieving by auth code
	retrievedByAuthCode, err := storage.GetGrantByAuthCode(context.Background(), authCode)
	if err != nil {
		t.Fatalf("failed to get grant by auth code: %v", err)
	}
	if retrievedByAuthCode == nil {
		t.Fatal("expected grant to be found by auth code")
	}
	if retrievedByAuthCode.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrievedByAuthCode.ID)
	}

	// Test retrieving by refresh token
	retrievedByRefreshToken, err := storage.GetGrantByRefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("failed to get grant by refresh token: %v", err)
	}
	if retrievedByRefreshToken == nil {
		t.Fatal("expected grant to be found by refresh token")
	}
	if retrievedByRefreshToken.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrievedByRefreshToken.ID)
	}

	// Test expiring a grant
	if err := storage.ExpireGrant(context.Background(), grantID); err != nil {
		t.Fatalf("failed to expire grant: %v", err)
	}

	// Test that expired grant is not returned
	expiredGrant, err := storage.GetGrant(context.Background(), grantID)
	if err != nil {
		t.Fatalf("failed to get expired grant: %v", err)
	}
	if expiredGrant != nil {
		t.Error("expected expired grant to be nil")
	}
}
