package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"

	"github.com/lstoll/idp/oidc"
	"github.com/lstoll/idp/saml"
	"github.com/sirupsen/logrus"
)

func main() {
	l := logrus.New()
	// TODO

	conn := &SimpleConnector{
		Logger: l,
		Users: map[string]string{
			"user": "password",
		},
	}

	stor := &MemStorage{}

	cp := &ClientProvider{}

	// pass this the SimpleConnector. Have it create the dex connector, and call initialize on SimpleConn

	svr, err := oidc.NewServer(l, stor, conn, cp, "http://127.0.0.1:5556")
	if err != nil {
		log.Fatal(err)
	}

	mux := chi.NewMux()

	mux.Use(NewStructuredLogger(l))

	svr.MountRoutes(mux)

	mux.Post("/login", conn.LoginPost)

	ssvr, err := saml.NewServer(l, stor, conn, cp, "http://127.0.0.1:5556")
	if err != nil {
		log.Fatal(err)
	}
	ssvr.MountRoutes(mux)

	log.Fatal(http.ListenAndServe("127.0.0.1:5556", mux))
}
