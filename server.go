package main

import (
	"context"
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
	providers       map[string]Provider
	storage         Storage
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

	w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>title</title>
    <link rel="stylesheet" href="style.css">
    <script src="script.js"></script>
  </head>
  <body>`))

	for id, p := range s.providers {
		panel, err := p.LoginPanel(req, ar)
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `<div id="%s-panel">`, id)
		w.Write([]byte(panel))
		w.Write([]byte(`</div>`))
	}

	w.Write([]byte(`</body>
	</html>`))
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

		// oauth2 proxy wants this, when we don't have useinfo
		// TODO - scopes/userinfo etc.
		idt.Extra["email"] = email
		idt.Extra["email_verified"] = true

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
	mux.HandleFunc("/token", s.token)
}

type authSessionManager struct {
	storage Storage
	oidcsvr *core.OIDC
}

func (a *authSessionManager) GetMetadata(ctx context.Context, sessionID string, into interface{}) (ok bool, err error) {
	md, ok, err := a.storage.GetMetadata(ctx, sessionID)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(md.ProviderMetadata, into); err != nil {
		return false, fmt.Errorf("unmarshaling provider metadata: %v", err)
	}
	return true, nil
}

func (a *authSessionManager) PutMetadata(ctx context.Context, sessionID string, d interface{}) error {
	md, ok, err := a.storage.GetMetadata(ctx, sessionID)
	if err != nil {
		return err
	}
	if !ok {
		md = Metadata{}
	}
	md.ProviderMetadata, err = json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshaling provider metadata: %v", err)
	}
	return nil
}

func (a *authSessionManager) Authenticate(w http.ResponseWriter, req *http.Request, sessionID string, auth *Authentication) {
	md, ok, err := a.storage.GetMetadata(req.Context(), sessionID)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	if !ok {
		md = Metadata{}
	}
	md.Claims, err = json.Marshal(auth.Claims)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	if err := a.storage.PutMetadata(req.Context(), sessionID, md); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	a.oidcsvr.FinishAuthorization(w, req, sessionID, auth.Authorization)
}
