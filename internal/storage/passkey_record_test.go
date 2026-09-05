package storage

import (
	"bytes"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyRecordRoundTrip(t *testing.T) {
	cred := testRegistrationCredential(t)
	record, err := EncodePasskeyRecord(cred)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, "$webauthn$v=1$") {
		t.Fatalf("record = %q", record)
	}
	payload := record[strings.LastIndex(record, "$")+1:]
	if strings.ContainsAny(payload, "-_") {
		t.Fatalf("payload uses base64url, want standard base64: %q", payload)
	}

	got, err := CredentialFromPasskeyRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ID) != string(cred.ID) {
		t.Fatalf("credential id mismatch")
	}
	if string(got.PublicKey) != string(cred.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestPasskeyRecordFromAttestationObject(t *testing.T) {
	cred := testRegistrationCredential(t)
	if len(cred.Attestation.Object) == 0 {
		t.Fatal("expected attestation object")
	}
	cred.Attestation.AuthenticatorData = nil

	record, err := EncodePasskeyRecord(cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CredentialFromPasskeyRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ID) != string(cred.ID) {
		t.Fatalf("credential id mismatch")
	}
}

func TestPasskeyRecordDedupsAndSortsTransports(t *testing.T) {
	cred := testRegistrationCredential(t)
	cred.Transport = []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid, protocol.Internal}
	record, err := EncodePasskeyRecord(cred)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, "$webauthn$v=1$transports=hybrid+internal$") {
		t.Fatalf("record = %q", record)
	}
}

func TestPasskeyRecordRejectsAssertionAuthData(t *testing.T) {
	raw := make([]byte, 37)
	_, err := EncodePasskeyRecord(&webauthn.Credential{
		Attestation: webauthn.CredentialAttestation{AuthenticatorData: raw},
	})
	if err == nil {
		t.Fatal("expected error for auth data without AT flag")
	}
}

func testRegistrationCredential(t *testing.T) *webauthn.Credential {
	t.Helper()
	wn, err := webauthn.New(&webauthn.Config{
		RPID:          "test.example.com",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &testPasskeyUser{id: []byte("abcdefghijklmnopqrstuvwxyz")}
	options, sessionData, err := wn.BeginRegistration(user)
	if err != nil {
		t.Fatal(err)
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = user.id
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
			UserID:          string(user.id),
			UserName:        "test@example.com",
			UserDisplayName: "Test User",
		},
	)
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader([]byte(attestationResponse)))
	if err != nil {
		t.Fatal(err)
	}
	created, err := wn.CreateCredential(user, *sessionData, parsedResponse)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

type testPasskeyUser struct {
	id []byte
}

func (u *testPasskeyUser) WebAuthnID() []byte                         { return u.id }
func (u *testPasskeyUser) WebAuthnName() string                       { return "test@example.com" }
func (u *testPasskeyUser) WebAuthnDisplayName() string                { return "Test User" }
func (u *testPasskeyUser) WebAuthnIcon() string                       { return "" }
func (u *testPasskeyUser) WebAuthnCredentials() []webauthn.Credential { return nil }
