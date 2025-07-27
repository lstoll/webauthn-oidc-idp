package auth

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lstoll/web"
	"github.com/lstoll/web/httperror"
	"github.com/lstoll/web/session"
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
	LoggedinUserID *string
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
}

func (a *Authenticator) AddHandlers(r *web.Server) {
	r.Handle("GET /{$}", a.Middleware(web.BrowserHandlerFunc(a.HandleIndex)))
	r.Handle("GET /login", web.BrowserHandlerFunc(a.HandleLoginPage), SkipAuthn)
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
		if !ok || as.LoggedinUserID == nil {
			a.TriggerLogin(w, r, r.URL.Path)
			return
		}

		// TODO: check if the user is logged in, this is where we'll redirect to
		// the login page if they are not.
		next.ServeHTTP(w, r)
	})
}

// HandleIndex is a temporary handler, just to get a webauthn UI up and running.
func (a *Authenticator) HandleIndex(ctx context.Context, w web.ResponseWriter, r *web.Request) error {

	// Example: User not logged in
	return w.WriteResponse(r, &web.TemplateResponse{
		Name: "login.html.tmpl",
		Data: webcommon.LayoutData{
			Title:        "Login - IDP",
			UserLoggedIn: false,
			Username:     "",
		},
		Templates: webcommon.Templates,
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

	_ = response

	// here we'll render the login page, just show a hello world for now. we
	// should track the login info / return to in the session.
	return w.WriteResponse(r, &web.TemplateResponse{
		Templates: templates,
		Name:      "login.tmpl.html",
		Data: loginData{
			LayoutData: webcommon.LayoutData{
				Title: "Login - IDP",
			},
			FlowID:            flowID,
			WebauthnChallenge: string(response.Response.Challenge),
		},
	})
}

func (a *Authenticator) DoLogin(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	// this will handle the login request, and return the user to the
	// appropriate page.
	return nil
}
