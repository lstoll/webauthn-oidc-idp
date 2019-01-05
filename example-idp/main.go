package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"

	"github.com/lstoll/idp/oidc"
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

	// pass this the SimpleConnector. Have it create the dex connector, and call initialize on SimpleConn

	svr, err := oidc.NewServer(l, stor, conn)
	if err != nil {
		log.Fatal(err)
	}

	mux := chi.NewMux()

	mux.Use(NewStructuredLogger(l))

	svr.MountRoutes(mux)

	mux.Post("/login", conn.LoginPost)

	log.Fatal(http.ListenAndServe("127.0.0.1:5556", mux))
}
