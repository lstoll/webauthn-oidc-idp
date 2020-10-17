package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"net/http"

	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"

	upstreamAllowQuery = "data.upstream.allow"
)

type server struct {
	issuer          string
	oidcsvr         *core.OIDC
	oidccli         *oidc.Client
	storage         *DynamoStore
	tokenValidFor   time.Duration
	refreshValidFor time.Duration

	// upstreamPolicy is rego code applied to claims from upstream IDP
	upstreamPolicy []byte
}

func (s *server) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidcsvr.StartAuthorization(w, req)
	if err != nil {
		log.Printf("error starting authorization: %v", err)
		return
	}

	http.Redirect(w, req, s.oidccli.AuthCodeURL(ar.SessionID), http.StatusFound)
}

func (s *server) callback(w http.ResponseWriter, req *http.Request) {
	if errMsg := req.FormValue("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("error returned to callback %s: %s", errMsg, req.FormValue("error_description")), http.StatusInternalServerError)
		return
	}

	code := req.FormValue("code")
	if code == "" {
		http.Error(w, "no code in callback response", http.StatusBadRequest)
		return
	}

	state := req.FormValue("state")
	if state == "" {
		http.Error(w, "no state in callback response", http.StatusBadRequest)
		return
	}

	token, err := s.oidccli.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("error exchanging code for token: %v", err), http.StatusInternalServerError)
		return
	}

	policyOK, err := evalClaimsPolicy(req.Context(), s.upstreamPolicy, upstreamAllowQuery, token.Claims)
	if err != nil {
		http.Error(w, "evaluating policy", http.StatusInternalServerError)
		return
	}
	if !policyOK {
		http.Error(w, "denied by policy", http.StatusForbidden)
		return
	}

	auth := &core.Authorization{
		Scopes: []string{"openid"},
	}

	cljson, err := json.Marshal(token.Claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("claims to json: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.storage.PutMetadata(req.Context(), state, Metadata{
		Claims: cljson,
	}); err != nil {
		http.Error(w, fmt.Sprintf("putting metadata: %v", err), http.StatusInternalServerError)
		return
	}

	// finalize it. this will redirect the user to the appropriate place
	if err := s.oidcsvr.FinishAuthorization(w, req, state, auth); err != nil {
		log.Printf("error finishing authorization: %v", err)
	}
}

func (s *server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidcsvr.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		// This is how we could update our metadata
		meta, ok, err := s.storage.GetMetadata(req.Context(), tr.SessionID)
		if err != nil {
			return nil, fmt.Errorf("getting metadata for session %s", tr.SessionID)
		}
		if !ok {
			return nil, fmt.Errorf("no metadata for session %s", tr.SessionID)
		}

		var claims oidc.Claims
		if err := json.Unmarshal(meta.Claims, &claims); err != nil {
			return nil, fmt.Errorf("unmarshaling claims: %v", err)
		}

		email, ok := claims.Extra["email"].(string)
		if !ok {
			return nil, fmt.Errorf("email claim not found")
		}

		idt := tr.PrefillIDToken(s.issuer, email, time.Now().Add(s.tokenValidFor))

		return &core.TokenResponse{
			AccessTokenValidUntil:  time.Now().Add(s.tokenValidFor),
			RefreshTokenValidUntil: time.Now().Add(s.refreshValidFor),
			IssueRefreshToken:      tr.SessionRefreshable, // always allow it if we want it
			IDToken:                idt,
		}, nil
	})
	if err != nil {
		log.Printf("error in token endpoint: %v", err)
	}
}

func (s *server) AddHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/auth", s.authorization)
	mux.HandleFunc("/callback", s.callback)
	mux.HandleFunc("/token", s.token)
}
