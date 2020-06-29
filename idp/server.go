package main

import (
	"fmt"
	"html/template"
	"log"
	"strings"
	"time"

	"net/http"

	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"
)

type server struct {
	issuer          string
	oidc            *core.OIDC
	storage         *DynamoStore
	tokenValidFor   time.Duration
	refreshValidFor time.Duration
}

const loginPage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<h1>Log in to IDP</h1>
		<form action="/finish" method="POST">
			<p>Subject: <input type="text" name="subject" value="auser" required size="15"></p>
			<p>Granted Scopes (space delimited): <input type="text" name="scopes" value="{{ .scopes }}" size="15"></p>
			<p>ACR: <input type="text" name="acr" size="15"></p>
			<p>AMR (comma delimited): <input type="text" name="amr" value="{{ .amr }}" size="15"></p>
			<p>Userinfo: <textarea name="userinfo" rows="10" cols="30">{"name": "A User"}</textarea></p>
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var loginTmpl = template.Must(template.New("loginPage").Parse(loginPage))

func (s *server) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidc.StartAuthorization(w, req)
	if err != nil {
		log.Printf("error starting authorization: %v", err)
		return
	}

	// set a cookie with the auth ID, so we can track it.
	aidc := &http.Cookie{
		Name:   sessIDCookie,
		Value:  ar.SessionID,
		MaxAge: 600,
	}
	http.SetCookie(w, aidc)

	var acr string
	if len(ar.ACRValues) > 0 {
		acr = ar.ACRValues[0]
	}
	tmplData := map[string]interface{}{
		"acr":    acr,
		"scopes": strings.Join(ar.Scopes, " "),
	}

	w.Header().Set("content-type", "text/html; charset=utf8")

	if err := loginTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) finishAuthorization(w http.ResponseWriter, req *http.Request) {
	sessID, err := req.Cookie(sessIDCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get auth id cookie: %v", err), http.StatusInternalServerError)
		return
	}

	var amr []string
	if req.FormValue("amr") != "" {
		amr = strings.Split(req.FormValue("amr"), ",")
	}

	auth := &core.Authorization{
		Scopes: strings.Split(req.FormValue("scopes"), " "),
		ACR:    req.FormValue("acr"),
		AMR:    amr,
	}

	// We have the session ID. This is stable for the session, so we can track
	// whatever we want along with it. We always get the session ID in later
	// requests, so we can always pull things out

	if err := s.storage.PutMetadata(req.Context(), sessID.Value, Metadata{
		Subject:  req.FormValue("subject"),
		Userinfo: map[string]interface{}{},
	}); err != nil {
		http.Error(w, fmt.Sprintf("putting metadata: %v", err), http.StatusInternalServerError)
		return
	}

	// finalize it. this will redirect the user to the appropriate place
	if err := s.oidc.FinishAuthorization(w, req, sessID.Value, auth); err != nil {
		log.Printf("error finishing authorization: %v", err)
	}
}

func (s *server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		// This is how we could update our metadata
		meta, ok, err := s.storage.GetMetadata(req.Context(), tr.SessionID)
		if err != nil {
			return nil, fmt.Errorf("getting metadata for session %s", tr.SessionID)
		}
		if !ok {
			return nil, fmt.Errorf("no metadata for session %s", tr.SessionID)
		}
		_ = meta

		idt := tr.PrefillIDToken(s.issuer, meta.Subject, time.Now().Add(s.tokenValidFor))

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
	mux.HandleFunc("/finish", s.finishAuthorization)
	mux.HandleFunc("/token", s.token)
}
