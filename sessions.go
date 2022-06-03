package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
)

const webSessionIDCookieName = "session-id"

func init() {
	gob.Register(sessions.Session{})
}

type gorillaSession struct {
	sessions.Session
}

func (g *gorillaSession) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(g.Session); err != nil {
		return nil, fmt.Errorf("encoding session: %w", err)
	}
	b, err := json.Marshal(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("json marshaling gob session: %w", err)
	}
	return b, nil
}

func (g *gorillaSession) UnmarshalJSON(b []byte) error {
	var db []byte
	if err := json.Unmarshal(b, &db); err != nil {
		return fmt.Errorf("unmarshaling json %s: %v", string(b), err)
	}
	if err := gob.NewDecoder(bytes.NewReader(db)).Decode(&g.Session); err != nil {
		return fmt.Errorf("gob decoding session: %w", err)
	}
	return nil
}

type webSession struct {
	// SessionID is the unique ID that should be used to track this session,
	// likely via setting a cookie.
	SessionID string `json:"-"`

	GorillaSessions map[string]*gorillaSession `json:"gorilla_sessions,omitempty"`

	// TODO - make this a generic or something so we can have a test object?
	TestCounter int `json:"test_counter,omitempty"`
}

// Empty return true if the session contains no data, if this is the case the
// session should not be saved
func (w *webSession) Empty() bool {
	return len(w.GorillaSessions) == 0 &&
		w.TestCounter == 0
}

const sessionIDCookie = "session-id"

type webSessionStore interface {
	// GetWebSession returns the session for the given ID. if no session, ok will be
	// false.
	GetWebSession(ctx context.Context, key string) (sess *webSession, ok bool, err error)
	// CreateWebSession returns a new, unpersisted session for use
	CreateWebSession(ctx context.Context) (*webSession, error)
	// PutWebSession persists the given session
	PutWebSession(ctx context.Context, sess *webSession, validFor time.Duration) error
	// DeleteWebSession removes the session for the given ID.
	DeleteWebSession(ctx context.Context, key string) error
}

type sessionManager struct {
	st webSessionStore

	sessionValidityTime time.Duration
}

func (s *sessionManager) sessionForRequest(r *http.Request) (*webSession, error) {
	c, err := r.Cookie(webSessionIDCookieName)
	if err == http.ErrNoCookie {
		// start a new session
		nsess, err := s.st.CreateWebSession(r.Context())
		if err != nil {
			return nil, fmt.Errorf("getting cookie %s: %v", webSessionIDCookieName, err)
		}
		return nsess, nil
	}

	ctxLog(r.Context()).Debugf("got cookie %#v", c)

	// we have the cookie
	dbsess, ok, err := s.st.GetWebSession(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	if ok {
		ctxLog(r.Context()).Debugf("return DB sess %s", dbsess.SessionID)
		return dbsess, nil
	}

	// couldn't find the session, start new
	sess, err := s.st.CreateWebSession(r.Context())
	if err != nil {
		return nil, err
	}
	ctxLog(r.Context()).Debugf("return new sess ID %s", sess.SessionID)

	return sess, nil
}

func (s *sessionManager) saveSession(ctx context.Context, w http.ResponseWriter, sess *webSession) error {
	if sess.Empty() {
		ctxLog(ctx).Debugf("not saving session %s to DB, it is empty", sess.SessionID)
		return nil
	}
	ctxLog(ctx).Debugf("saving session %s to DB", sess.SessionID)

	if err := s.st.PutWebSession(ctx, sess, s.sessionValidityTime); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:  webSessionIDCookieName,
		Value: sess.SessionID,
		Path:  "/",

		Expires: time.Now().Add(s.sessionValidityTime - 1*time.Minute), // fudge the cookie to be valid slightly less than the DB
		Secure:  true,                                                  // we should always serve tls
	})
	return nil
}

var _ sessions.Store = (*webSession)(nil)

// Get is a gorilla sessions.Store compat method
//
// This just hits the cache
func (w *webSession) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(w, name)
}

// New is a gorilla sessions.Store compat method
//
// this should load it, or create a new one
func (w *webSession) New(_ *http.Request, name string) (*sessions.Session, error) {
	s, ok := w.GorillaSessions[name]
	if ok {
		return &s.Session, nil
	}
	return sessions.NewSession(w, name), nil
}

func (w *webSession) Save(_ *http.Request, _ http.ResponseWriter, session *sessions.Session) error {
	if w.GorillaSessions == nil {
		w.GorillaSessions = map[string]*gorillaSession{}
	}
	w.GorillaSessions[session.Name()] = &gorillaSession{*session}
	return nil
}

var _ sessions.Store = (*sessionShim)(nil)

// sessionShim can be passed in to things that require a session store outside
// the request context. It will just use what's in the contex.
type sessionShim struct{}

// Get is a gorilla sessions.Store compat method
//
// This just hits the cache
func (s *sessionShim) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessionFromContext(r.Context()).Get(r, name)
}

// New is a gorilla sessions.Store compat method
//
// this should load it, or create a new one
func (s *sessionShim) New(r *http.Request, name string) (*sessions.Session, error) {
	return sessionFromContext(r.Context()).New(r, name)

}

func (s *sessionShim) Save(r *http.Request, rw http.ResponseWriter, session *sessions.Session) error {
	return sessionFromContext(r.Context()).Save(r, rw, session)
}
