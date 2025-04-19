package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lstoll/cookiesession"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/webauthn-oidc-idp/web"
)

/* keeping this around as some context betweet a oidc/session, and an authentication


// AuthSessionManager is responsible for managing an auth session throughout
// it's lifecycle, from the moment a user decides to authenticate via us until
// the credentials expire or are revoked. This is essentially a companion of
// github.com/lstoll/oidc/core/SessionManager , for tracking our application
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

var (
	loginTemplate = template.Must(template.ParseFS(web.Templates, "templates/login.tmpl.html"))
)

type oidcServer struct {
	issuer  string
	oidcsvr *core.OIDC
	// providers []Provider
	// asm             AuthSessionManager
	tokenValidFor   time.Duration
	refreshValidFor time.Duration
	eh              *httpErrHandler
	sessmgr         *cookiesession.Manager[webSession, *webSession]
	webauthn        *webauthn.WebAuthn
	db              *DB
}

func (s *oidcServer) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidcsvr.StartAuthorization(w, req)
	if err != nil {
		slog.ErrorContext(req.Context(), "start authorization", logErr(err))
		return
	}

	// stash in session, so we can pull it out in the login handler without
	// threading it through the user code. make sure to clear it though!
	sess := s.sessmgr.Get(req.Context())
	sess.WebauthnLogin = &webauthnLoginData{
		LoginSessionID: ar.SessionID,
	}
	s.sessmgr.Save(req.Context(), sess)

	if err := loginTemplate.Execute(w, struct{ SessionID string }{SessionID: ar.SessionID}); err != nil {
		slog.Error("execute login.html.tmpl", logErr(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (s *oidcServer) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidcsvr.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		auth, err := s.db.GetAuthenticatedUser(tr.SessionID) // this smelt a bit previously
		if err != nil {
			return nil, fmt.Errorf("get authentication for session %s", tr.SessionID)
		}

		idt := tr.PrefillIDToken(auth.Subject, time.Now().Add(s.tokenValidFor))
		at := tr.PrefillAccessToken(auth.Subject, time.Now().Add(s.tokenValidFor))

		// oauth2 proxy wants this, when we don't have userinfo
		// also our middleware doesn't suppor userinfo
		// TODO(lstoll) decide on what we include here, what is userinfo etc. for now, include enough to work with
		// TODO(lstoll) respond correctly based on scopes
		idt.Extra["email"] = auth.Email
		idt.Extra["email_verified"] = true
		idt.Extra["picture"] = gravatarURL(auth.Email) // thank u tom
		idt.Extra["name"] = auth.FullName

		return &core.TokenResponse{
			RefreshTokenValidUntil: time.Now().Add(s.refreshValidFor),
			IssueRefreshToken:      tr.SessionRefreshable, // always allow it if we want it
			AccessToken:            at,
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
	mux.HandleFunc("GET /userinfo", s.userinfo)
}

func (s *oidcServer) startLogin(rw http.ResponseWriter, req *http.Request) {
	response, sessionData, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		slog.Error("starting discoverable login", logErr(err))
		s.httpErr(rw, errors.New("no active login session"))
		return
	}

	sess := s.sessmgr.Get(req.Context())
	if sess.WebauthnLogin == nil {
		s.httpErr(rw, errors.New("no active login session"))
		return
	}
	sess.WebauthnLogin.WebauthnSessionData = sessionData
	s.sessmgr.Save(req.Context(), sess)

	if err := json.NewEncoder(rw).Encode(response); err != nil {
		s.httpErr(rw, err)
		return
	}
}

func (s *oidcServer) finishLogin(rw http.ResponseWriter, req *http.Request) {
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(req.Body)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("parsing credential creation response: %v", err))
		return
	}

	userID := string(parsedResponse.Response.UserHandle) // user handle is the webauthn.User#ID we registered with

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		s.httpErr(rw, err)
		return
	}

	// var car protocol.CredentialAssertionResponse

	// if err := json.NewDecoder(req.Body).Decode(&car); err != nil {
	// 	s.httpErr(rw, err)
	// 	return
	// }
	// log.Printf("car: %#v", car)

	sess := s.sessmgr.Get(req.Context())
	if sess == nil {
		s.httpErr(rw, fmt.Errorf("session data not in session"))
		return
	}
	if sess.WebauthnLogin == nil || sess.WebauthnLogin.WebauthnSessionData == nil {
		s.httpErr(rw, errors.New("no valid webauthn login in session"))
		return
	}
	sessionData := *sess.WebauthnLogin.WebauthnSessionData
	sess.WebauthnLogin.WebauthnSessionData = nil
	s.sessmgr.Save(req.Context(), sess)

	// parsedResponse, err := protocol.ParseCredentialRequestResponseBody(req.Body)
	// if err != nil {
	// 	s.httpErr(rw, fmt.Errorf("parsing credential creation response: %v", err))
	// 	return
	// }
	sessionData.UserID = parsedResponse.Response.UserHandle // need this for the validation
	credential, err := s.webauthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("validating login: %v", err))
		return
	}

	// update the credential for the counter etc.
	if err := s.db.UpdateUserCredential(user.ID, *credential); err != nil {
		s.httpErr(rw, err)
		return
	}

	// TODO inline the session authentication, and send the user directly to the
	// finalize page. Having this extra step was a result of the providers
	// interface iirc. Or maybe it's an OIDC library limitation, either way we
	// should look at how to flatten it.
	sess.WebauthnLogin.AuthdUser = &webauthnLogin{
		UserID:      user.ID,
		SessionID:   sess.WebauthnLogin.LoginSessionID,
		ValidBefore: time.Now().Add(15 * time.Second), // TODO - policy etc.
	}
	sess.WebauthnLogin.LoginSessionID = ""
	s.sessmgr.Save(req.Context(), sess)

	// OK (respond with URL here)
}

func (s *oidcServer) loggedIn(rw http.ResponseWriter, req *http.Request) {
	sess := s.sessmgr.Get(req.Context())

	if sess.WebauthnLogin == nil || sess.WebauthnLogin.AuthdUser == nil {
		s.httpErr(rw, fmt.Errorf("can't find authd_user in session"))
		return
	}
	authdUser := *sess.WebauthnLogin.AuthdUser
	sess.WebauthnLogin = nil
	s.sessmgr.Save(req.Context(), sess)

	if authdUser.ValidBefore.Before(time.Now()) {
		s.httpErr(rw, fmt.Errorf("login expired"))
		return
	}

	user, err := s.db.GetUserByID(authdUser.UserID)
	if err != nil {
		s.httpErr(rw, err)
		return
	}

	// This is a user-facing redirect item. We might need to update upstream to
	// help do it more inline with webauthn info. In the mean time we have the
	// webauthn page redirect here, with the user ID in the session. we can get
	// the user info out of this, and then finalize the session and let it
	// render Access issues, or a redirect to the final location.

	// finalize it. this will redirect the user to the appropriate place
	auth := AuthenticatedUser{
		Subject:  user.ID,
		Email:    user.Email,
		FullName: user.FullName,
		// TODO other fields
	}

	// todo - what is/was this actually doing? It's on
	// our custom storage type, so diff to oidc?
	// https://github.com/lstoll/idp/blob/bc90facd5b6ea40d95f4f71c255f74d0a3bb5f83/storage_dynamo_sessions.go#L195-L247
	if err := s.db.Authenticate(authdUser.SessionID, auth); err != nil {
		s.httpErr(rw, fmt.Errorf("authenticating user for session id %s: %w", authdUser.SessionID, err))
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
	_ = s.oidcsvr.FinishAuthorization(rw, req, authdUser.SessionID, az)
}

func (s *oidcServer) userinfo(w http.ResponseWriter, req *http.Request) {
	err := s.oidcsvr.Userinfo(w, req, func(w io.Writer, uireq *core.UserinfoRequest) error {
		u, err := s.db.GetUserByID(uireq.Subject)
		if err != nil {
			return fmt.Errorf("getting user %s: %w", uireq.Subject, err)
		}

		// TODO(lstoll) pass through the scopes, use them to decide what to
		// reurn. For now all info is good enough, we don't have a consent
		// process anyway.
		//
		// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
		cl := oidc.IDClaims{
			Issuer:  s.issuer,
			Subject: uireq.Subject,
			Extra:   make(map[string]any),
		}
		cl.Extra["email"] = u.Email
		cl.Extra["email_verified"] = true
		cl.Extra["picture"] = gravatarURL(u.Email) // thank u tom
		cl.Extra["name"] = u.FullName
		nsp := strings.Split(u.FullName, " ")
		if len(nsp) == 2 {
			cl.Extra["given_name"] = nsp[0]
			cl.Extra["family_name"] = nsp[1]
		}
		// cl.Extra["preferred_username"] TODO(lstoll) just e-email? do we want a username field?

		return json.NewEncoder(w).Encode(cl)
	})
	if err != nil {
		s.eh.Error(w, req, err)
	}
}

func (s *oidcServer) httpErr(rw http.ResponseWriter, err error) {
	// TODO - replace me with the error handler
	slog.Error("(TODO improve this handler) error in server", logErr(err))
	http.Error(rw, "Internal Error", http.StatusInternalServerError)
}

func gravatarURL(email string) string {
	hash := md5.Sum([]byte(email))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x.png", hash)
}
