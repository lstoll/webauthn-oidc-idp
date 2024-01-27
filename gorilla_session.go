package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/gorilla/sessions"
)

func init() {
	gob.Register(sessions.Session{})
}

// gorillaSCSStore wraps a scs session, in a way that can be used like a gorilla
// session. This is needed for the OIDC middleware, it would probably be cooler
// if it didn't need that.
type gorillaSCSStore struct {
	sm *scs.SessionManager
}

var _ sessions.Store = (*gorillaSCSStore)(nil)

func (g *gorillaSCSStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(g, name)
}

// New is a gorilla sessions.Store compat method
//
// this should load it, or create a new one
func (g *gorillaSCSStore) New(r *http.Request, name string) (*sessions.Session, error) {
	b := g.sm.GetBytes(r.Context(), fmt.Sprintf("gorilla-%s", name))
	if b == nil {
		return sessions.NewSession(g, name), nil
	}
	var out sessions.Session
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&out); err != nil {
		return nil, fmt.Errorf("error decoding gorilla data for %s from session: %w", name, err)
	}
	return &out, nil
}

func (g *gorillaSCSStore) Save(r *http.Request, _ http.ResponseWriter, session *sessions.Session) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(*session); err != nil {
		return fmt.Errorf("encoding login data: %w", err)
	}
	g.sm.Put(r.Context(), fmt.Sprintf("gorilla-%s", session.Name()), buf.Bytes())
	return nil
}
