package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
	"uuid"

	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/storage"
	"lds.li/web/httperror"
	"lds.li/web/webtest"
)

func TestHandleListAndDeleteCredentials(t *testing.T) {
	userID := uuid.New()
	otherID := uuid.New()
	legacyID := uuid.New()
	passkeyID := uuid.New()
	otherPasskeyID := uuid.New()

	credStore, err := storage.NewCredentialFile(t.TempDir() + "/credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:        legacyID,
			UserID:    userID,
			Name:      "legacy-key",
			CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		})
		cs.AddPasskey(userID, nil, &storage.Passkey{
			ID:        passkeyID,
			Name:      "phone",
			CreatedAt: time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC),
		})
		cs.AddPasskey(otherID, nil, &storage.Passkey{
			ID:   otherPasskeyID,
			Name: "other",
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	auth := &Authenticator{CredStore: credStore}
	as := appsession.Auth{
		LoggedInUserID: &userID,
		ExpiresAt:      time.Now().Add(time.Hour),
	}

	req, _ := requestWithSession(t, "GET", "/api/credentials", appsession.Data{Auth: as})
	rw := webtest.NewResponse()
	if err := auth.HandleListCredentials(req.RawRequest().Context(), rw, req); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rw.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	var listed listCredentialsResponse
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	if len(listed.Credentials) != 2 {
		t.Fatalf("listed %d credentials, want 2: %s", len(listed.Credentials), body)
	}
	if listed.Credentials[0].ID != passkeyID.String() || listed.Credentials[0].Name != "phone" {
		t.Fatalf("want newest passkey first, got %+v", listed.Credentials[0])
	}
	if listed.Credentials[1].ID != legacyID.String() {
		t.Fatalf("want legacy second, got %+v", listed.Credentials[1])
	}

	delReq, _ := requestWithSession(t, "DELETE", "/api/credentials/"+otherPasskeyID.String(), appsession.Data{Auth: as})
	delRW := webtest.NewResponse()
	err = auth.HandleDeleteCredential(delReq.RawRequest().Context(), delRW, delReq)
	var httpErr httperror.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Code() != http.StatusNotFound {
		t.Fatalf("delete other user's passkey: %v", err)
	}

	delReq, _ = requestWithSession(t, "DELETE", "/api/credentials/"+passkeyID.String(), appsession.Data{Auth: as})
	delRW = webtest.NewResponse()
	if err := auth.HandleDeleteCredential(delReq.RawRequest().Context(), delRW, delReq); err != nil {
		t.Fatal(err)
	}
	if delRW.Result().StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d, want %d", delRW.Result().StatusCode, http.StatusNoContent)
	}

	req, _ = requestWithSession(t, "GET", "/api/credentials", appsession.Data{Auth: as})
	rw = webtest.NewResponse()
	if err := auth.HandleListCredentials(req.RawRequest().Context(), rw, req); err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(rw.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Credentials) != 1 || listed.Credentials[0].ID != legacyID.String() {
		t.Fatalf("after delete got %+v", listed.Credentials)
	}
}
