package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"database/sql"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lstoll/web"
	"github.com/lstoll/web/httperror"
	"github.com/lstoll/web/session"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/internal/webcommon"
)

func init() {
	gob.Register(&authSess{})
}

const (
	authSessSessionKey = "auth-sess"
	authFlowValidFor   = 10 * time.Minute
)

type ctxKeySkipAuthn struct{}

var _ web.HandlerOpt = SkipAuthn

// SkipAuthn is a handler option that skips authentication for the request.
func SkipAuthn(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeySkipAuthn{}, true))
}

type authSess struct {
	LoggedinUserID uuid.NullUUID
	Flows          map[string]authSessFlow
}

type authSessFlow struct {
	ID       string
	ReturnTo string
	// WebauthnData is the data for the webauthn login, for this flow.
	WebauthnData *webauthn.SessionData
	StartedAt    time.Time
}

type Authenticator struct {
	Webauthn *webauthn.WebAuthn
	Queries  *queries.Queries
}

type webauthnUser struct {
	user        queries.User
	overrideID  []byte
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return u.overrideID
}

func (u *webauthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	return u.user.FullName
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (a *Authenticator) AddHandlers(r *web.Server) {
	r.Handle("GET /{$}", a.Middleware(web.BrowserHandlerFunc(a.HandleIndex)))
	r.Handle("GET /login", web.BrowserHandlerFunc(a.HandleLoginPage), SkipAuthn)
	r.Handle("GET /logout", web.BrowserHandlerFunc(a.Logout), SkipAuthn)
	r.Handle("POST /finishWebauthnLogin", web.BrowserHandlerFunc(a.DoLogin), SkipAuthn)
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip, ok := r.Context().Value(ctxKeySkipAuthn{}).(bool)
		if ok && skip {
			next.ServeHTTP(w, r)
			return
		}

		sess, _ := session.FromContext(r.Context())
		as, ok := sess.Get(authSessSessionKey).(*authSess)
		if !ok || !as.LoggedinUserID.Valid {
			a.TriggerLogin(w, r, r.URL.Path)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HandleIndex is a temporary handler, just to get a webauthn UI up and running.
func (a *Authenticator) HandleIndex(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	as, ok := r.Session().Get(authSessSessionKey).(*authSess)
	if !ok || !as.LoggedinUserID.Valid {
		return httperror.ForbiddenErrf("session missing user info")
	}

	// Example: User not logged in
	return w.WriteResponse(r, &web.TemplateResponse{
		Name: "index.tmpl.html",
		Data: webcommon.LayoutData{
			Title:        "Login - IDP",
			UserLoggedIn: true,
			Username:     as.LoggedinUserID.UUID.String(),
		},
		Templates: templates,
	})
}

func (a *Authenticator) TriggerLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	// we'll want something to manually kick off the login flow, to use with
	// oauth2 as we'll want to process the request first. This should maybe take
	// a return to, and return the ID or something so the caller can link to it.
	// E.g process oauth2 start, get the URL to trigger a login, store the
	// oauth2 request info in the session, then send the user onwards to login.
	// The returnto should be called with the ID or something in the query
	// param.
	//
	// alt, the caller can include this in the returnto it generates.

	sess, _ := session.FromContext(r.Context())
	as, ok := sess.Get(authSessSessionKey).(*authSess)
	if !ok {
		as = &authSess{}
	}
	if as.Flows == nil {
		as.Flows = make(map[string]authSessFlow)
	}

	id := uuid.New()

	as.Flows[id.String()] = authSessFlow{
		ReturnTo:  returnTo,
		StartedAt: time.Now(),
	}

	sess.Set(authSessSessionKey, as)

	http.Redirect(w, r, fmt.Sprintf("/login?flow=%s", id.String()), http.StatusFound)
}

func (a *Authenticator) HandleLoginPage(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	flowID := r.URL().Query().Get("flow")
	if flowID == "" {
		return httperror.BadRequestErrf("flow is required")
	}

	as, ok := r.Session().Get(authSessSessionKey).(*authSess)
	if !ok {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[flowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	response, sessionData, err := a.Webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return fmt.Errorf("starting discoverable login: BeginDiscoverableLogin: %w", err)
	}

	flow.WebauthnData = sessionData
	as.Flows[flowID] = flow
	r.Session().Set(authSessSessionKey, as)

	return w.WriteResponse(r, &web.TemplateResponse{
		Templates: templates,
		Name:      "login.tmpl.html",
		Data: loginData{
			LayoutData: webcommon.LayoutData{
				Title: "Login - IDP",
			},
			FlowID:            flowID,
			WebauthnChallenge: base64.RawURLEncoding.EncodeToString(response.Response.Challenge),
		},
	})
}

type loginRequest struct {
	FlowID                      string          `json:"flowID"`
	CredentialAssertionResponse json.RawMessage `json:"credentialAssertionResponse"`
}

type loginResponse struct {
	ReturnTo string `json:"returnTo"`
	Error    string `json:"error"`
}

func (a *Authenticator) DoLogin(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	var req loginRequest
	if err := r.UnmarshalJSONBody(&req); err != nil {
		return fmt.Errorf("unmarshalling login request: %w", err)
	}

	as, ok := r.Session().Get(authSessSessionKey).(*authSess)
	if !ok {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[req.FlowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.CredentialAssertionResponse))
	if err != nil {
		return fmt.Errorf("parsing credential assertion response: %w", err)
	}

	// Validate the login
	user, credential, err := a.Webauthn.ValidatePasskeyLogin(a.NewDiscoverableUserHandler(ctx), *flow.WebauthnData, parsedResponse)
	if err != nil {
		return fmt.Errorf("validating login: %w", err)
	}

	// Update credential data
	cb, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshalling credential: %w", err)
	}

	if err := a.Queries.UpdateCredentialDataByCredentialID(ctx, cb, credential.ID); err != nil {
		return fmt.Errorf("updating credential: %w", err)
	}

	// Set user ID in session
	delete(as.Flows, req.FlowID)
	as.LoggedinUserID = uuid.NullUUID{UUID: user.(*webauthnUser).user.ID, Valid: true}
	r.Session().Set(authSessSessionKey, as)

	// Return the flow's returnTo URL
	return w.WriteResponse(r, &web.JSONResponse{
		Data: loginResponse{
			ReturnTo: flow.ReturnTo,
		},
	})
}

func (a *Authenticator) Logout(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	r.Session().Delete()
	return w.WriteResponse(r, &web.RedirectResponse{
		URL: "/",
	})
}

func (a *Authenticator) NewDiscoverableUserHandler(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		var qu queries.User
		var validateID []byte

		// this handles a variety of userHandle formats, that we've used over
		// time. if we ever clean things up it would be nice to remove some of
		// the fallbacks.

		// If the userHandle is a valid UUID4 in bytes, use it directly
		if len(userHandle) == 16 && ((userHandle[6]&0xf0)>>4) == 4 {
			// it's a UUID4, likely the distinct webauthn handle
			handle, err := uuid.FromBytes(userHandle)
			if err != nil {
				return nil, fmt.Errorf("invalid UUIDv4: %w", err)
			}
			qu, err = a.Queries.GetUserByWebauthnHandle(ctx, handle)
			if err != nil {
				return nil, fmt.Errorf("getting user by webauthn handle: %w", err)
			}
			validateID = qu.WebauthnHandle[:]
		} else if err := uuid.Validate(string(userHandle)); err == nil {
			// string UUID, likely the user ID
			qu, err = a.Queries.GetUser(ctx, uuid.MustParse(string(userHandle)))
			if err != nil {
				return nil, fmt.Errorf("getting user by ID: %w", err)
			}
			validateID = []byte(qu.ID.String())
		} else {
			// process it as a fallback subject.
			qu, err = a.Queries.GetUserByOverrideSubject(ctx, sql.NullString{String: string(userHandle), Valid: true})
			if err != nil {
				return nil, fmt.Errorf("getting user by override subject: %w", err)
			}
			validateID = []byte(qu.OverrideSubject.String)
		}

		// Get user credentials
		creds, err := a.Queries.GetUserCredentials(ctx, qu.ID)
		if err != nil {
			return nil, fmt.Errorf("getting user credentials: %w", err)
		}

		wu := &webauthnUser{
			user:       qu,
			overrideID: validateID,
		}
		for _, c := range creds {
			var cred webauthn.Credential
			if err := json.Unmarshal(c.CredentialData, &cred); err != nil {
				return nil, fmt.Errorf("unmarshalling credential: %w", err)
			}
			wu.credentials = append(wu.credentials, cred)
		}

		return wu, nil
	}
}
