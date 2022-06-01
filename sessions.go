package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type webSession struct {
	// SessionID is the unique ID that should be used to track this session,
	// likely via setting a cookie.
	SessionID string `json:"-"`
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
	var sess *webSession
	c, err := r.Cookie(sessIDCookie)
	if err == http.ErrNoCookie {
		// start a new session
		nsess, err := s.st.CreateWebSession(r.Context())
		if err != nil {
			return nil, fmt.Errorf("getting cookie %s: %v", sessIDCookie, err)
		}
		sess = nsess
	} else {
		// we have the cookie
		dbsess, ok, err := s.st.GetWebSession(r.Context(), c.Value)
		if err != nil {
			return nil, err
		}
		if !ok {
			// couldn't find the session, start new
			sess, err = s.st.CreateWebSession(r.Context())
			if err != nil {
				return nil, err
			}
		} else {
			sess = dbsess
		}
	}

	return sess, nil
}

func (s *sessionManager) saveSession(ctx context.Context, w http.ResponseWriter, sess *webSession) error {
	if err := s.st.PutWebSession(ctx, sess, s.sessionValidityTime); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:  sessIDCookie,
		Value: sess.SessionID,

		Expires: time.Now().Add(s.sessionValidityTime - 1*time.Minute), // fudge the cookie to be valid slightly less than the DB
		Secure:  true,                                                  // we should aleways serve tls
	})
	return nil
}
