package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"encoding/base64"

	"bytes"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/session"
	"lds.li/session/sessiontest"
	"lds.li/web"
	"lds.li/web/webtest"
)

func TestWebauthnAuth(t *testing.T) {
	wn, err := webauthn.New(&webauthn.Config{
		RPID:          "test.example.com",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}

	credStore, err := storage.NewCredentialFile(t.TempDir() + "/credential-store.json")
	if err != nil {
		t.Fatalf("create credential store: %v", err)
	}

	auth := &Authenticator{
		Webauthn:  wn,
		CredStore: credStore,
		Config:    &config.Config{SessionDuration: config.JSONDuration(1 * time.Hour)},
	}

	t.Run("login_legacy", func(t *testing.T) {
		authenticator, credential, _ := createUserWithCredential(t, auth)
		as := doTestLogin(t, auth, authenticator, credential)

		t.Run("session_expiry", func(t *testing.T) {
			as.ExpiresAt = time.Now().Add(-1 * time.Second)

			req, _ := requestWithSession(t, "GET", "/",
				appsession.Data{Auth: as},
			)
			rw := webtest.NewResponse()

			if err := auth.HandleIndex(req.RawRequest().Context(), rw, req); err == nil {
				t.Error("expected error due to expired session, got nil")
			} else if !strings.Contains(err.Error(), "user not logged in") {
				t.Errorf("expected 'user not logged in' error, got: %v", err)
			}
		})
	})

	t.Run("login_c2sp", func(t *testing.T) {
		authenticator, credential, _ := createUserWithPasskeyRecord(t, auth)
		doTestLogin(t, auth, authenticator, credential)
	})
}

func doTestLogin(t *testing.T, auth *Authenticator, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential) appsession.Auth {
	t.Helper()

	as := appsession.Auth{}

	lrw := httptest.NewRecorder()
	lrr := httptest.NewRequest("GET", "/needredir", nil)
	auth.TriggerLogin(lrw, lrr, "/dashboard")

	if lrw.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", lrw.Result().StatusCode)
	}
	if lrw.Result().Header.Get("Location") == "" {
		t.Fatalf("expected redirect, got no location")
	}

	if len(as.Flows) != 0 {
		t.Fatalf("expected no flows to be created in session during TriggerLogin, got %d", len(as.Flows))
	}

	req, change := requestWithSession(t, "GET", lrw.Result().Header.Get("Location"),
		appsession.Data{Auth: as},
		webtest.RequestWithStaticContent(webcommon.Static, "/static"),
	)

	rw := webtest.NewResponse()
	if err := auth.HandleLoginPage(req.RawRequest().Context(), rw, req); err != nil {
		t.Fatalf("handle login page: %v", err)
	}

	if rw.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status OK, got %d", rw.Result().StatusCode)
	}

	body, err := io.ReadAll(rw.Result().Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	reFlowID := regexp.MustCompile(`<div\s+data-flow-id="([^"]+)"`)
	reChallenge := regexp.MustCompile(`<div\s+data-webauthn-challenge="([^"]+)"`)

	flowIDMatch := reFlowID.FindSubmatch(body)
	if flowIDMatch == nil {
		t.Fatalf("could not find data-flow-id in response body")
	}
	extractedFlowID := string(flowIDMatch[1])

	challengeMatch := reChallenge.FindSubmatch(body)
	if challengeMatch == nil {
		t.Fatalf("could not find data-webauthn-challenge in response body")
	}
	extractedChallenge := string(challengeMatch[1])

	challengeBytes, err := base64.RawURLEncoding.DecodeString(extractedChallenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		virtualwebauthn.RelyingParty{
			ID:     "test.example.com",
			Name:   "Test",
			Origin: "https://example.com",
		},
		authenticator,
		credential,
		virtualwebauthn.AssertionOptions{
			Challenge:      challengeBytes,
			RelyingPartyID: "test.example.com",
		},
	)

	var assertionData map[string]any
	if err := json.Unmarshal([]byte(assertionResponse), &assertionData); err != nil {
		t.Fatalf("unmarshal assertion response: %v", err)
	}

	loginData := map[string]any{
		"flowID":                      extractedFlowID,
		"credentialAssertionResponse": assertionData,
	}

	loginReq, loginChange := requestWithSession(t, "POST", "/finishWebauthnLogin",
		change.Data(),
		webtest.RequestWithJSONBody(loginData),
	)

	loginRw := webtest.NewResponse()
	if err := auth.DoLogin(loginReq.RawRequest().Context(), loginRw, loginReq); err != nil {
		t.Fatalf("do login: %v", err)
	}

	if loginRw.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected login status OK, got %d", loginRw.Result().StatusCode)
	}

	loginResponseBody, err := io.ReadAll(loginRw.Result().Body)
	if err != nil {
		t.Fatalf("read login response body: %v", err)
	}

	var loginResponse struct {
		ReturnTo string `json:"returnTo"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(loginResponseBody, &loginResponse); err != nil {
		t.Fatalf("unmarshal login response: %v", err)
	}

	if loginResponse.Error != "" {
		t.Fatalf("login failed with error: %s", loginResponse.Error)
	}

	as = loginChange.Data().Auth
	if as.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt not set after login")
	}
	if as.AuthenticatedAt.IsZero() {
		t.Fatal("AuthenticatedAt not set after login")
	}
	return as
}

// Helper function to create a user with a registered credential. When we re-do
// registration, we should probably replace this with that.
func createUserWithCredential(t *testing.T, auth *Authenticator) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, uuid.UUID) {
	userID := uuid.New()
	webauthnHandle := uuid.New()

	auth.Config.Users = append(auth.Config.Users, &config.User{
		ID:             userID,
		Email:          "test@example.com",
		FullName:       "Test User",
		WebauthnHandle: webauthnHandle,
	})

	// Create a webauthn user for registration
	wu := &WebAuthnUser{
		user: &config.User{
			ID:             userID,
			Email:          "test@example.com",
			FullName:       "Test User",
			WebauthnHandle: webauthnHandle,
		},
		webAuthnID: webauthnHandle[:],
	}

	// Begin registration
	options, sessionData, err := auth.Webauthn.BeginRegistration(wu)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}

	// Create virtual authenticator for registration
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = webauthnHandle[:]
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(credential)

	// Create attestation response
	challengeBytes := []byte(options.Response.Challenge)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{
			ID:     "test.example.com",
			Name:   "Test",
			Origin: "https://example.com",
		},
		authenticator,
		credential,
		virtualwebauthn.AttestationOptions{
			Challenge:       challengeBytes,
			RelyingPartyID:  "test.example.com",
			UserID:          string(webauthnHandle[:]),
			UserName:        "test@example.com",
			UserDisplayName: "Test User",
		},
	)

	// Create the credential using go-webauthn
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader([]byte(attestationResponse)))
	if err != nil {
		t.Fatalf("parse credential creation response: %v", err)
	}

	createdCredential, err := auth.Webauthn.CreateCredential(wu, *sessionData, parsedResponse)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:             uuid.New(),
			CredentialID:   createdCredential.ID,
			CredentialData: createdCredential,
			Name:           "Test Credential",
			UserID:         userID,
		})
		return nil
	}); err != nil {
		t.Fatalf("write credential to store: %v", err)
	}

	return authenticator, credential, webauthnHandle
}

func createUserWithPasskeyRecord(t *testing.T, auth *Authenticator) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, uuid.UUID) {
	t.Helper()
	userID := uuid.New()
	webauthnHandle := uuid.New()
	user := &config.User{
		ID:             userID,
		Email:          "c2sp@example.com",
		FullName:       "C2SP User",
		WebauthnHandle: webauthnHandle,
	}
	auth.Config.Users = append(auth.Config.Users, user)

	var passkeyUserID string
	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		pu := cs.EnsurePasskeyUser(userID, user.PasskeyHandleAliases())
		passkeyUserID = pu.PasskeyUserID
		return nil
	}); err != nil {
		t.Fatalf("ensure passkey user: %v", err)
	}

	wu := NewWebAuthnUser(user, passkeyUserID, nil)
	options, sessionData, err := auth.Webauthn.BeginRegistration(wu)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = []byte(passkeyUserID)
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(credential)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{
			ID:     "test.example.com",
			Name:   "Test",
			Origin: "https://example.com",
		},
		authenticator,
		credential,
		virtualwebauthn.AttestationOptions{
			Challenge:       []byte(options.Response.Challenge),
			RelyingPartyID:  "test.example.com",
			UserID:          passkeyUserID,
			UserName:        user.Email,
			UserDisplayName: user.FullName,
		},
	)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader([]byte(attestationResponse)))
	if err != nil {
		t.Fatalf("parse credential creation response: %v", err)
	}

	createdCredential, err := auth.Webauthn.CreateCredential(wu, *sessionData, parsedResponse)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	record, err := storage.EncodePasskeyRecord(createdCredential)
	if err != nil {
		t.Fatalf("encode passkey record: %v", err)
	}

	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		cs.AddPasskey(userID, user.PasskeyHandleAliases(), &storage.Passkey{
			ID:        uuid.New(),
			Record:    record,
			Name:      "C2SP Credential",
			CreatedAt: time.Now(),
		})
		return nil
	}); err != nil {
		t.Fatalf("write passkey: %v", err)
	}

	return authenticator, credential, webauthnHandle
}

func requestWithSession(t *testing.T, method, url string, data appsession.Data, opts ...webtest.RequestOpt) (*web.Request, *sessiontest.Change[appsession.Data]) {
	t.Helper()
	req := webtest.NewRequest(method, url, opts...)
	manager, err := session.NewKVManager[appsession.Data](session.NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, change := sessiontest.WithSession(t, req.RawRequest(), manager, data)
	raw = raw.WithContext(appsession.WithManagerContext(raw.Context(), manager))
	return web.NewRequestFrom(raw), change
}
