package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"lds.li/passidp/internal/appsession"
)

func TestAuthTimeFromContext(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	req, _ := requestWithSession(t, "GET", "/", appsession.Data{Auth: appsession.Auth{
		LoggedInUserID:  uuid.NullUUID{UUID: userID, Valid: true},
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(time.Hour),
	}})

	got, ok := AuthTimeFromContext(req.RawRequest().Context())
	if !ok {
		t.Fatal("expected auth time")
	}
	if !got.Equal(now) {
		t.Fatalf("AuthenticatedAt = %v, want %v", got, now)
	}

	t.Run("expired session", func(t *testing.T) {
		req, _ := requestWithSession(t, "GET", "/", appsession.Data{Auth: appsession.Auth{
			LoggedInUserID:  uuid.NullUUID{UUID: userID, Valid: true},
			AuthenticatedAt: now,
			ExpiresAt:       now.Add(-time.Second),
		}})
		if _, ok := AuthTimeFromContext(req.RawRequest().Context()); ok {
			t.Fatal("expected no auth time for expired session")
		}
	})
}
