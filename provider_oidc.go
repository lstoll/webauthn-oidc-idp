package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
)

var (
	_ embedProvider  = (*OIDCProvider)(nil)
	_ http.Handler   = (*OIDCProvider)(nil)
	_ UpstreamPolicy = (*config)(nil)
)

type UpstreamPolicy interface {
	HasUpstreamClaimsPolicy() bool
	UpstreamClaimsPolicy() (string, error)
}

type OIDCProvider struct {
	name    string
	oidccli *oidc.Client
	asm     AuthSessionManager
	// up is a rego policy applied to the claims we receive
	// from the upstream provider, before finalizing the auth
	up UpstreamPolicy
	eh *httpErrHandler
}

func (o *OIDCProvider) LoginPanel(r *http.Request, ar *core.AuthorizationRequest) (template.HTML, error) {
	// TODO - box with link to s.oidccli.AuthCodeURL(ar.SessionID)
	return template.HTML(fmt.Sprintf(`
<p>
<a href="%s">Log In With %s</a>
</p>`, o.oidccli.AuthCodeURL(ar.SessionID), o.name,
	)), nil
}

func (o *OIDCProvider) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" || req.URL.Path != "/callback" {
		log.Printf("path %v", req.URL.Path)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if errMsg := req.FormValue("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("error returned to callback %s: %s", errMsg, req.FormValue("error_description")), http.StatusInternalServerError)
		return
	}

	code := req.FormValue("code")
	if code == "" {
		o.eh.BadRequest(w, req, "no code in callback response")
		return
	}

	state := req.FormValue("state")
	if state == "" {
		o.eh.BadRequest(w, req, "no state in callback response")
		return
	}

	token, err := o.oidccli.Exchange(req.Context(), code)
	if err != nil {
		o.eh.Error(w, req, fmt.Errorf("error exchanging code for token: %v", err))
		return
	}

	if o.up.HasUpstreamClaimsPolicy() {
		p, err := o.up.UpstreamClaimsPolicy()
		if err != nil {
			o.eh.Error(w, req, fmt.Errorf("fetching policy: %v", err))
			return
		}

		policyOK, err := evalClaimsPolicy(req.Context(), []byte(p), upstreamAllowQuery, token.Claims)
		if err != nil {
			o.eh.Error(w, req, fmt.Errorf("evaluating policy: %v", err))
			return
		}
		if !policyOK {
			o.eh.Forbidden(w, req, "denied by policy")
			return
		}
	}

	cljson, err := json.Marshal(token.Claims)
	if err != nil {
		o.eh.Error(w, req, fmt.Errorf("claims to json: %v", err))
		return
	}

	if err := o.asm.PutMetadata(req.Context(), state, Metadata{
		Claims: cljson,
	}); err != nil {
		o.eh.Error(w, req, fmt.Errorf("putting metadata: %v", err))
		return
	}

	// finalize it. this will redirect the user to the appropriate place
	o.asm.Authenticate(w, req, state, Authentication{
		Subject: token.Claims.Subject,
		EMail:   token.Claims.Extra["email"].(string), // TODO
		// TODO other fields
	})
}
