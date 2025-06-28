package idp

import (
	"crypto/md5"
	"database/sql"
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
	"github.com/google/uuid"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/core"
	"github.com/lstoll/web"
	"github.com/lstoll/web/session"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	webcontent "github.com/lstoll/webauthn-oidc-idp/web"
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
	loginTemplate = template.Must(template.ParseFS(webcontent.Templates, "templates/login.tmpl.html"))
)

type oidcServer struct {
	issuer  string
	oidcsvr *core.OIDC
	// providers []Provider
	// asm             AuthSessionManager
	tokenValidFor   time.Duration
	refreshValidFor time.Duration
	webauthn        *webauthn.WebAuthn
	db              *DB
	queries         *queries.Queries
}

func (s *oidcServer) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidcsvr.StartAuthorization(w, req)
	if err != nil {
		slog.ErrorContext(req.Context(), "start authorization", "err", err)
		return
	}

	// stash in session, so we can pull it out in the login handler without
	// threading it through the user code. make sure to clear it though!
	sess := session.MustFromContext(req.Context())
	sess.Set(webauthnLoginDataSessionKey, &webauthnLoginData{
		LoginSessionID: ar.SessionID,
	})

	if err := loginTemplate.Execute(w, struct{ SessionID string }{SessionID: ar.SessionID}); err != nil {
		slog.Error("execute login.html.tmpl", "err", err)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *oidcServer) AddHandlers(websvr *web.Server) {
	websvr.HandleFunc("/auth", s.authorization)
	websvr.HandleFunc("/token", s.token)
	websvr.HandleFunc("/start", s.startLogin)
	websvr.HandleFunc("/finish", s.finishLogin)
	websvr.HandleFunc("/loggedin", s.loggedIn)
	websvr.HandleFunc("GET /userinfo", s.userinfo)
}

func (s *oidcServer) startLogin(rw http.ResponseWriter, req *http.Request) {
	response, sessionData, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		slog.Error("starting discoverable login", "err", err)
		s.httpErr(rw, errors.New("no active login session"))
		return
	}

	sess := session.MustFromContext(req.Context())
	wl, ok := sess.Get(webauthnLoginDataSessionKey).(*webauthnLoginData)
	if !ok || wl.WebauthnSessionData == nil {
		s.httpErr(rw, errors.New("no active login session"))
		return
	}
	wl.WebauthnSessionData = sessionData
	sess.Set(webauthnLoginDataSessionKey, wl)

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

	// userHandle is what we registered the credential with. Currently this is a
	// unique value just for this purpose, but previously could have been the
	// user ID. which also could now be the override subject. So try them all.
	// If it's the new handle, it'll be bytes. If it's one of the older ID
	// types, it'll be a string.
	// TODO(lstoll) clean this up at some point, might need to re-register some
	// things.
	var (
		user queries.User
		// validateID is the ID we'll use to validate the user later.
		// go-webauthn requires it to align with what the credential provided.
		validateID []byte
	)
	// If the userHandle is a valid UUID4 in bytes, use it directly
	if len(parsedResponse.Response.UserHandle) == 16 && ((parsedResponse.Response.UserHandle[6]&0xf0)>>4) == 4 {
		// it's a UUID4, likely the distinct webauthn handle
		userHandle, err := uuid.FromBytes(parsedResponse.Response.UserHandle)
		if err != nil {
			s.httpErr(rw, fmt.Errorf("invalid UUIDv4: %v", err))
			return
		}
		user, err = s.queries.GetUserByWebauthnHandle(req.Context(), userHandle)
		if err != nil {
			s.httpErr(rw, fmt.Errorf("getting user by webauthn handle: %v", err))
			return
		}
		validateID = user.WebauthnHandle[:]
	} else if err := uuid.Validate(string(parsedResponse.Response.UserHandle)); err == nil {
		// string UUID, likely the user ID
		user, err = s.queries.GetUser(req.Context(), uuid.MustParse(string(parsedResponse.Response.UserHandle)))
		if err != nil {
			s.httpErr(rw, fmt.Errorf("getting user by ID: %v", err))
			return
		}
		validateID = []byte(user.ID.String())
	} else {
		// process it as a fallback subject.
		user, err = s.queries.GetUserByOverrideSubject(req.Context(), sql.NullString{String: string(parsedResponse.Response.UserHandle), Valid: true})
		if err != nil {
			s.httpErr(rw, fmt.Errorf("getting user by override subject: %v", err))
			return
		}
		validateID = []byte(user.OverrideSubject.String)
	}

	// var car protocol.CredentialAssertionResponse

	// if err := json.NewDecoder(req.Body).Decode(&car); err != nil {
	// 	s.httpErr(rw, err)
	// 	return
	// }
	// log.Printf("car: %#v", car)

	sess := session.MustFromContext(req.Context())
	wl, ok := sess.Get(webauthnLoginDataSessionKey).(*webauthnLoginData)
	if !ok || wl.WebauthnSessionData == nil {
		s.httpErr(rw, fmt.Errorf("session data not in session"))
		return
	}
	sessionData := *wl.WebauthnSessionData
	sess.Set(webauthnLoginDataSessionKey, nil)

	// parsedResponse, err := protocol.ParseCredentialRequestResponseBody(req.Body)
	// if err != nil {
	// 	s.httpErr(rw, fmt.Errorf("parsing credential creation response: %v", err))
	// 	return
	// }
	sessionData.UserID = parsedResponse.Response.UserHandle // need this for the validation

	creds, err := s.queries.GetUserCredentials(req.Context(), user.ID)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("getting user credentials: %v", err))
		return
	}

	wu := &webauthnUser{
		qu:         user,
		overrideID: validateID,
	}
	for _, c := range creds {
		var cred webauthn.Credential
		if err := json.Unmarshal(c.CredentialData, &cred); err != nil {
			s.httpErr(rw, fmt.Errorf("unmarshalling credential: %v", err))
			return
		}
		wu.wc = append(wu.wc, cred)
	}

	credential, err := s.webauthn.ValidateLogin(wu, sessionData, parsedResponse)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("validating login: %v", err))
		return
	}

	cb, err := json.Marshal(credential)
	if err != nil {
		s.httpErr(rw, fmt.Errorf("marshalling credential: %v", err))
		return
	}

	if err := s.queries.UpdateCredentialDataByCredentialID(req.Context(), cb, credential.ID); err != nil {
		s.httpErr(rw, fmt.Errorf("updating credential: %v", err))
		return
	}

	// TODO inline the session authentication, and send the user directly to the
	// finalize page. Having this extra step was a result of the providers
	// interface iirc. Or maybe it's an OIDC library limitation, either way we
	// should look at how to flatten it.
	wl.AuthdUser = &webauthnLogin{
		UserID:      user.ID.String(),
		SessionID:   wl.LoginSessionID,
		ValidBefore: time.Now().Add(15 * time.Second), // TODO - policy etc.
	}
	wl.LoginSessionID = ""
	sess.Set(webauthnLoginDataSessionKey, wl)

	// OK (respond with URL here)
}

func (s *oidcServer) loggedIn(rw http.ResponseWriter, req *http.Request) {
	sess := session.MustFromContext(req.Context())
	wl, ok := sess.Get(webauthnLoginDataSessionKey).(*webauthnLoginData)
	if !ok || wl.AuthdUser == nil {
		s.httpErr(rw, fmt.Errorf("can't find authd_user in session"))
		return
	}
	authdUser := *wl.AuthdUser
	sess.Set(webauthnLoginDataSessionKey, nil)

	if authdUser.ValidBefore.Before(time.Now()) {
		s.httpErr(rw, fmt.Errorf("login expired"))
		return
	}

	user, err := s.queries.GetUser(req.Context(), uuid.MustParse(authdUser.UserID))
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
		Email:    user.Email,
		FullName: user.FullName,
		// TODO other fields
	}
	if user.OverrideSubject.Valid && user.OverrideSubject.String != "" {
		auth.Subject = user.OverrideSubject.String
	} else {
		auth.Subject = user.ID.String()
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
		u, err := s.queries.GetUser(req.Context(), uuid.MustParse(uireq.Subject))
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *oidcServer) httpErr(rw http.ResponseWriter, err error) {
	// TODO - replace me with the error handler
	slog.Error("(TODO improve this handler) error in server", "err", err)
	http.Error(rw, "Internal Error", http.StatusInternalServerError)
}

func gravatarURL(email string) string {
	hash := md5.Sum([]byte(email))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x.png", hash)
}

// webauthnUser is a wrapper around the queries.User type that implements the
// webauthn.User interface for that library to consume
type webauthnUser struct {
	qu         queries.User
	overrideID []byte
	wc         []webauthn.Credential
}

// WebAuthnID returns the webauthn user handle for the user
func (u *webauthnUser) WebAuthnID() []byte {
	if len(u.overrideID) > 0 {
		return u.overrideID
	}
	return u.qu.WebauthnHandle[:]
}

func (u *webauthnUser) WebAuthnName() string {
	return u.qu.Email
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.qu.FullName
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.wc
}
