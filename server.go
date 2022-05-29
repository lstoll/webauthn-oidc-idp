package main

import (
	_ "embed"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"time"

	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"

	upstreamAllowQuery = "data.upstream.allow"

	webauthnSessionName = "wa"
)

/* keeping this around as some context betweet a oidc/session, and an authentication


// AuthSessionManager is responsible for managing an auth session throughout
// it's lifecycle, from the moment a user decides to authenticate via us until
// the credentials expire or are revoked. This is essentially a companion of
// github.com/pardot/oidc/core/SessionManager , for tracking our application
// specific items. It can associate and retrieve relevant metadata with a
// session. In addition, it can mark a session as authenticated, moving it from
// the gathering user info stage in to the tokens issued/refreshed stage.
type AuthSessionManager interface {
	// GetMetadata retrieves provider-specific metadata for the given session in
	// to the provided json-compatible object. If no metadata is found, ok will
	// be false.
	GetMetadata(ctx context.Context, sessionID string, into interface{}) (ok bool, err error)
	// PutMetadata stores the json-marshalable, provider specific data
	// associated with the given session.
	PutMetadata(ctx context.Context, sessionID string, d interface{}) error

	// Authenticate should be called at the end of the providers authentication
	// flow, to provide details about who was authenticated for the sesion. This
	// should be passed the http request and non-started response, it will
	// handle the next steps.
	Authenticate(w http.ResponseWriter, req *http.Request, sessionID string, auth Authentication)
	// GetAuthentication returns the authentication details for a sesion, if
	// authenticated
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
} */

//go:embed web/templates/login.tmpl.html
var webauthnLoginTemplate string

type oidcServer struct {
	issuer  string
	oidcsvr *core.OIDC
	// providers []Provider
	// asm             AuthSessionManager
	tokenValidFor   time.Duration
	refreshValidFor time.Duration

	eh *httpErrHandler

	/* here on is old webauthn provider stuff
	   TODO - merge field better */
	store    WebauthnUserStore
	webauthn *webauthn.WebAuthn

	/* here on is the authsessionmanager stuff
	   TODO - merge better */
	storage Storage
}

func (s *oidcServer) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidcsvr.StartAuthorization(w, req)
	if err != nil {
		log.Printf("error starting authorization: %v", err)
		return
	}

	template.Must(template.New("login").Parse(webauthnLoginTemplate)).Execute(w, struct {
		SessionID string
	}{
		SessionID: ar.SessionID,
	})
}

func (s *oidcServer) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidcsvr.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		auth, ok, err := s.storage.GetAuthentication(req.Context(), tr.SessionID) // this smelt a bit previously
		if err != nil {
			return nil, fmt.Errorf("getting authentication for session %s", tr.SessionID)
		}
		if !ok {
			return nil, fmt.Errorf("no authentication for session %s", tr.SessionID)
		}

		idt := tr.PrefillIDToken(s.issuer, auth.Subject, time.Now().Add(s.tokenValidFor))

		// oauth2 proxy wants this, when we don't have useinfo
		// TODO - scopes/userinfo etc.
		idt.Extra["email"] = auth.EMail
		idt.Extra["email_verified"] = true

		return &core.TokenResponse{
			AccessTokenValidUntil:  time.Now().Add(s.tokenValidFor),
			RefreshTokenValidUntil: time.Now().Add(s.refreshValidFor),
			IssueRefreshToken:      tr.SessionRefreshable, // always allow it if we want it
			IDToken:                idt,
		}, nil
	})
	if err != nil {
		s.eh.Error(w, req, err)
	}
}

func (s *oidcServer) AddHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/auth", s.authorization)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/start", s.startLogin)
	mux.HandleFunc("/finish", s.finishLogin)
	mux.HandleFunc("/loggedin", s.loggedIn)
}

func (s *oidcServer) startLogin(rw http.ResponseWriter, req *http.Request) {
	email := req.URL.Query().Get("email")

	log.Printf("start for %s", email)

	u, ok, err := s.store.GetUserByEmail(req.Context(), email)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	if !ok {
		// TODO - better response
		s.httpErr(rw, fmt.Errorf("no user for email"))
		return
	}

	options, sessionData, err := s.webauthn.BeginLogin(u)
	if err != nil {
		s.httpErr(rw, err)
		return
	}

	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	sess.Values["login"] = *sessionData
	if err := ss.Save(req, rw, sess); err != nil {
		s.httpErr(rw, err)
		return
	}

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		s.httpErr(rw, err)
		return
	}
}

func (s *oidcServer) finishLogin(rw http.ResponseWriter, req *http.Request) {
	var (
		email     = req.URL.Query().Get("email")
		sessionID = req.URL.Query().Get("sessionID")
	)

	u, ok, err := s.store.GetUserByEmail(req.Context(), email)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	if !ok {
		// TODO - better response
		s.httpErr(rw, fmt.Errorf("no user for email"))
		return
	}

	// var car protocol.CredentialAssertionResponse

	// if err := json.NewDecoder(req.Body).Decode(&car); err != nil {
	// 	s.httpErr(rw, err)
	// 	return
	// }
	// log.Printf("car: %#v", car)

	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	sessionData, ok := sess.Values["login"].(webauthn.SessionData)
	if !ok {
		s.httpErr(rw, fmt.Errorf("session data not in session"))
		return
	}
	delete(sess.Values, "login")

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(req.Body)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("parsing credential creation response: %v", err))
		return
	}
	credential, err := s.webauthn.ValidateLogin(u, sessionData, parsedResponse)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("validating login: %v", err))
		return
	}

	// update the credential for the counter etc.
	panic("TODO")
	if err := s.store.UpdateCredential(req.Context(), u.ID, *credential); err != nil {
		s.httpErr(rw, err)
		return
	}

	sess.Values["authd_user"] = webauthnLogin{
		UserID:      u.ID,
		SessionID:   sessionID,
		ValidBefore: time.Now().Add(15 * time.Second),
	}

	if err := ss.Save(req, rw, sess); err != nil {
		s.httpErr(rw, err)
		return
	}

	// OK (respond with URL here)
}

func (s *oidcServer) loggedIn(rw http.ResponseWriter, req *http.Request) {
	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	login, ok := sess.Values["authd_user"].(webauthnLogin)
	if !ok {
		s.httpErr(rw, fmt.Errorf("can't find authd_user in session"))
		return
	}
	delete(sess.Values, "authd_user")
	if err := ss.Save(req, rw, sess); err != nil {
		s.httpErr(rw, err)
		return
	}

	if login.ValidBefore.Before(time.Now()) {
		s.httpErr(rw, fmt.Errorf("login expired"))
		return
	}

	u, ok, err := s.store.GetUserByID(req.Context(), login.UserID)
	if err != nil {
		s.httpErr(rw, err)
		return
	}
	if !ok {
		s.httpErr(rw, fmt.Errorf("no user found"))
		return
	}

	// This is a user-facing redirect item. We might need to update upstream to
	// help do it more inline with webauthn info. In the mean time we have the
	// webauthn page redirect here, with the user ID in the session. we can get
	// the user info out of this, and then finalize the session and let it
	// render Access issues, or a redirect to the final location.

	// finalize it. this will redirect the user to the appropriate place
	auth := Authentication{
		Subject:  u.ID,
		EMail:    u.Email,
		FullName: u.FullName,
		// TODO other fields
	}

	// todo - what is/was this actually doing? It's on
	// our custom storage type, so diff to oidc?
	// https://github.com/lstoll/idp/blob/bc90facd5b6ea40d95f4f71c255f74d0a3bb5f83/storage_dynamo_sessions.go#L195-L247
	if err := s.storage.Authenticate(req.Context(), login.SessionID, auth); err != nil {
		s.httpErr(rw, fmt.Errorf("no user found"))
		return
	}
	// TODO - we need to fill this. This is likely going to need information
	// about the provider (acr), requested claims, etc. This probably goes in
	// the server metadata field
	az := &core.Authorization{
		Scopes: []string{"openid"},
		// ACR:    a.provider.ACR(), TODO - acr?
		// AMR:    []string{a.provider.AMR()}, // TODO - amr?
	}
	s.oidcsvr.FinishAuthorization(rw, req, login.SessionID, az)
}

func (s *oidcServer) httpErr(rw http.ResponseWriter, err error) {
	panic("TODO - replace me with the error handler")
	http.Error(rw, "Internal Error", http.StatusInternalServerError)
}

type webauthnLogin struct {
	UserID      string
	ValidBefore time.Time
	SessionID   string
}

var _ = func() struct{} {
	gob.Register(webauthnLogin{})
	return struct{}{}
}()

var _ = func() struct{} {
	gob.Register(webauthnLogin{})
	return struct{}{}
}()
