package oidc

import (
	"context"
	"log"

	"github.com/sirupsen/logrus"

	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
	"github.com/go-chi/chi"
	"github.com/lstoll/idp"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type Server struct {
	dexServer *server.Server
	connector *DexConnector
}

// NewServer returns a http handler suitible for serving an OIDC provider
func NewServer(l logrus.FieldLogger, stor idp.Storage, conn idp.Connector) (*Server, error) {
	dc := &DexConnector{
		Wrapped:  conn,
		IDPStore: stor,
	}

	if err := conn.Initialize(dc); err != nil {
		log.Fatal(err)
	}

	server.ConnectorsConfig["idp"] = func() server.ConnectorConfig { return dc }

	conns := []storage.Connector{
		{
			ID:   ConnectorID,
			Name: "idp",
			Type: "idp",
		},
	}

	cfg := server.Config{
		Logger:             l,
		PrometheusRegistry: prometheus.NewRegistry(),
		Web: server.WebConfig{
			Dir: "vendor/github.com/dexidp/dex/web",
		},
		Issuer:  "http://127.0.0.1:5556",
		Storage: storage.WithStaticConnectors(&dstorage{Storage: stor, clientLookup: conn.OIDCClient}, conns),
	}
	dc.DexStore = cfg.Storage

	serv, err := server.NewServer(context.Background(), cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating dex server")
	}

	return &Server{dexServer: serv, connector: dc}, nil
}

// MountRoutes mounts the dex and connector HTTP routes on the given chi mux
func (s *Server) MountRoutes(mux *chi.Mux) {
	// These paths are extracted from dex's internals
	mux.Handle("/.well-known/openid-configuration", s.dexServer)
	mux.Handle("/token", s.dexServer)
	mux.Handle("/keys", s.dexServer)
	mux.Handle("/auth", s.dexServer)
	mux.Handle("/auth/{connector}", s.dexServer)
	mux.Handle("/callback/{connector}", s.dexServer)
	mux.Handle("/approval", s.dexServer)
	mux.Handle("/healthz", s.dexServer)
	mux.Handle("/static", s.dexServer)
	mux.Handle("/theme", s.dexServer)

	// Our bits
	mux.HandleFunc("/oidclogin/"+ConnectorID, s.connector.loginHandler)
}
