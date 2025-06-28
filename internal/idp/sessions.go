package idp

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

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
	LoginSessionID string `json:"login_session_id"`
	// WebauthnSessionData is the data for the in-process login
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// AuthdUser tracks information about the user we just authenticated, for
	// when we send the user to the login finished page.
	AuthdUser *webauthnLogin `json:"authd_user,omitempty"`
}

type webauthnLogin struct {
	UserID      string
	ValidBefore time.Time
	SessionID   string
}

type webSession struct {
	PendingWebauthnEnrollment *pendingWebauthnEnrollment `json:"pending_webauthn_enrollment,omitempty"`
	WebauthnLogin             *webauthnLoginData         `json:"webauthn_login,omitempty"`
}
