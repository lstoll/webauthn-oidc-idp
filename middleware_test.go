package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestMiddlewareSessions(t *testing.T) {
	ctx := context.Background()
	log := logrus.New()
	st := newTestStorage(t)
	smgr := &sessionManager{
		st:                  st,
		sessionValidityTime: 5 * time.Minute,
	}

	var testHandlerRun func(r *http.Request)
	wr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r.Context())
		sess.TestCounter++
		if testHandlerRun != nil {
			testHandlerRun(r)
		}
		// TODO - can the handler work if nothing is written?
		w.Write([]byte("OK"))
	})

	m := baseMiddleware(wr, log, smgr)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	m.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("no cookies set")
	}

	var sessIDCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == webSessionIDCookieName {
			sessIDCookie = c
		}
	}
	if sessIDCookie == nil {
		t.Fatal("no session ID cookie found")
	}
	if sessIDCookie.Value == "" {
		t.Fatal("sess ID cookie has empty ID")
	}

	wsess, ok, err := st.GetWebSession(ctx, sessIDCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("session not found in db for %s", sessIDCookie.Value)
	}
	if wsess.TestCounter != 1 {
		t.Error("counter should be incremented")
	}

	// try some gorilla shit
	testHandlerRun = func(r *http.Request) {
		sess := sessionFromContext(r.Context())
		gsess, err := sess.New(r, "tester")
		if err != nil {
			t.Fatal(err)
		}
		gsess.Values["key"] = "avalue"
		if err := gsess.Save(r, nil); err != nil {
			t.Fatal(err)
		}
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessIDCookie)

	m.ServeHTTP(rec, req)

	wsess, ok, err = st.GetWebSession(ctx, sessIDCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("session not found in db for %s", sessIDCookie.Value)
	}
	if wsess.TestCounter != 2 {
		t.Error("counter should be incremented")
	}

	t.Logf("wsess: %#v", wsess)

	gsess, err := wsess.New(req, "tester")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gsess: %#v", gsess)
	if gsess.Values["key"].(string) != "avalue" {
		t.Error("could not roundtrip in a gorilla session")
	}
}
