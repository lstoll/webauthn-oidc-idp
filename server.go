package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"net/http"

	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"

	upstreamAllowQuery = "data.upstream.allow"
)

type oidcServer struct {
	issuer          string
	oidcsvr         *core.OIDC
	providers       []Provider
	asm             AuthSessionManager
	tokenValidFor   time.Duration
	refreshValidFor time.Duration

	eh *httpErrHandler

	// upstreamPolicy is rego code applied to claims from upstream IDP
	upstreamPolicy []byte
}

func (s *oidcServer) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidcsvr.StartAuthorization(w, req)
	if err != nil {
		log.Printf("error starting authorization: %v", err)
		return
	}

	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>`))

	for _, p := range s.selectProviders(ar.ACRValues) {
		panel, err := p.LoginPanel(req, ar)
		if err != nil {
			s.eh.Error(w, req, err)
			return
		}
		fmt.Fprintf(w, `<div id="%s-panel">`, p.ID())
		w.Write([]byte(panel))
		w.Write([]byte(`</div>`))
	}

	w.Write([]byte(`</body>
	</html>`))
}

func (s *oidcServer) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidcsvr.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		auth, ok, err := s.asm.GetAuthentication(req.Context(), tr.SessionID)
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
}

// selectProviders filters the list down for a given ACR. if we don't have a
// match, return them all. this doesn't enforce the ACR, the consumer or later
// policy should set this
func (s *oidcServer) selectProviders(requestedACRs []string) []Provider {
	if len(requestedACRs) == 0 {
		return s.providers
	}
	ret := []Provider{}
	for _, p := range s.providers {
		for _, a := range requestedACRs {
			if p.ACR() == a {
				ret = append(ret, p)
			}
		}
	}
	if len(ret) > 0 {
		return ret
	}
	return s.providers
}

type authSessionManager struct {
	provider Provider
	storage  Storage
	oidcsvr  *core.OIDC
	eh       *httpErrHandler
}

func (a *authSessionManager) Authenticate(w http.ResponseWriter, req *http.Request, sessionID string, auth Authentication) {
	if err := a.storage.Authenticate(req.Context(), sessionID, auth); err != nil {
		a.eh.Error(w, req, err)
		return
	}
	// TODO - we need to fill this. This is likely going to need information
	// about the provider (acr), requested claims, etc. This probably goes in
	// the server metadata field
	az := &core.Authorization{
		Scopes: []string{"openid"},
		ACR:    a.provider.ACR(),
		AMR:    []string{a.provider.AMR()},
	}
	a.oidcsvr.FinishAuthorization(w, req, sessionID, az)
}

func (a *authSessionManager) GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error) {
	// this smells a bit
	return a.storage.GetAuthentication(ctx, sessionID)
}
