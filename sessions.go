package main

import (
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/cookiesession"
	"github.com/lstoll/oidc/middleware"
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
	LoginSessionID      string                `json:"login_session_id"`
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// AuthdUser tracks information about the user we just authenticated, for
	// when we send the user to the login finished page.
	AuthdUser *webauthnLogin `json:"authd_user,omitempty"`
}

type webSession struct {
	PendingWebauthnEnrollment *pendingWebauthnEnrollment `json:"pending_webauthn_enrollment,omitempty"`
	WebauthnLogin             *webauthnLoginData         `json:"webauthn_login,omitempty"`
}

func (webSession) SessionName() string {
	return "idp"
}

// oidcMiddlewareSession is the session we persist and load for the OIDC
// middleware. It just wraps the upstream data, so we can add a session name.
type oidcMiddlewareSession struct {
	middleware.SessionData
}

func (oidcMiddlewareSession) SessionName() string {
	return "oidc-mw"
}

type oidcMiddlewareSessionStore struct {
	mgr *cookiesession.Manager[oidcMiddlewareSession, *oidcMiddlewareSession]
}

// GetSession implements middleware.SessionStoreV2
func (o *oidcMiddlewareSessionStore) GetSession(r *http.Request) (*middleware.SessionData, error) {
	sd, _ := o.mgr.Get(r.Context())
	return &sd.SessionData, nil
}

// SaveSession implements middleware.SessionStoreV2
func (o *oidcMiddlewareSessionStore) SaveSession(_ http.ResponseWriter, r *http.Request, d *middleware.SessionData) error {
	sd, _ := o.mgr.Get(r.Context())
	sd.SessionData = *d
	o.mgr.Save(r.Context(), sd)
	return nil
}
