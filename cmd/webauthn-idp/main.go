package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"github.com/lstoll/idp/oidc"
	"github.com/lstoll/idp/saml"
	"github.com/lstoll/idp/session"
	"github.com/lstoll/idp/storage/memory"
	"github.com/lstoll/idp/webauthn"
	"github.com/sirupsen/logrus"
)

var (
	sessionKey string
)

func main() {
	flag.StringVar(&sessionKey, "session-key", string(securecookie.GenerateRandomKey(32)), "Key to secure cookie sessions")

	flag.Parse()

	l := logrus.New()
	// TODO

	stor := &memory.MemStorage{}
	us := &webauthn.UserStore{Storage: stor}

	if err := us.CreateUser("abcdef", "user", "password"); err != nil {
		log.Fatal(err)
	}

	conn, err := webauthn.NewConnector(l, us)
	if err != nil {
		log.Fatal(err)
	}

	cp := &ClientProvider{}

	svr, err := oidc.NewServer(l, stor, conn, cp, "http://localhost:5556")
	if err != nil {
		log.Fatal(err)
	}

	mux := chi.NewMux()

	mux.Use(session.ContextSession(sessions.NewCookieStore([]byte(sessionKey)), "idp"))

	mux.Use(NewStructuredLogger(l))

	svr.MountRoutes(mux)
	conn.MountRoutes(mux)

	ssvr, err := saml.NewServer(l, stor, conn, cp, "http://localhost:5556")
	if err != nil {
		log.Fatal(err)
	}
	ssvr.MountRoutes(mux)

	log.Fatal(http.ListenAndServe("localhost:5556", mux))
}
