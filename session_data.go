package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"

	"github.com/alexedwards/scs/v2"
	"github.com/duo-labs/webauthn/webauthn"
)

const (
	pendingEnrollmentKey = "pending-enrollment"
	webauthnLoginDataKey = "webauthn-login-data"
)

func init() {
	gob.Register(pendingWebauthnEnrollment{})
	gob.Register(webauthnLoginData{})
}

// pendingWebauthnEnrollment tracks enrollment info across an authenticator
// registration.
type pendingWebauthnEnrollment struct {
	ForUserID           string                `json:"for_user_id,omitempty"`
	KeyName             string                `json:"key_name,omitempty"`
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// ReturnTo redirects the user here after the key is registered.
	ReturnTo string `json:"return_to,omitempty"`
}

// webauthnLogin tracks data for a login session
type webauthnLoginData struct {
	// LoginSessionID is the current OIDC session ID for the flow
	LoginSessionID      string                `json:"login_session_id"`
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// AuthdUser tracks information about the user we just authenticated, for
	// when we send the user to the login finished page.
	AuthdUser *webauthnLogin `json:"authd_user,omitempty"`
}

func addEnrollmentToSession(ctx context.Context, sm *scs.SessionManager, data pendingWebauthnEnrollment) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return fmt.Errorf("encoding pending enrollment data: %w", err)
	}
	sm.Put(ctx, pendingEnrollmentKey, buf.Bytes())
	return nil
}

func popEnrollmentFromSession(ctx context.Context, sm *scs.SessionManager) (*pendingWebauthnEnrollment, error) {
	b := sm.PopBytes(ctx, pendingEnrollmentKey)
	if b == nil {
		return nil, nil
	}
	var out pendingWebauthnEnrollment
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&out); err != nil {
		return nil, fmt.Errorf("error decoding pending enrollment from session: %w", err)
	}
	return &out, nil
}

func addLoginDataToSession(ctx context.Context, sm *scs.SessionManager, data webauthnLoginData) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return fmt.Errorf("encoding login data: %w", err)
	}
	sm.Put(ctx, webauthnLoginDataKey, buf.Bytes())
	return nil
}

func popLoginDataFromSession(ctx context.Context, sm *scs.SessionManager) (*webauthnLoginData, error) {
	b := sm.PopBytes(ctx, webauthnLoginDataKey)
	if b == nil {
		return nil, nil
	}
	var out webauthnLoginData
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&out); err != nil {
		return nil, fmt.Errorf("error decoding login data from session: %w", err)
	}
	return &out, nil
}
