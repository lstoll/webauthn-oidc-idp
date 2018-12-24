package oidcserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/lstoll/idp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	// "github.com/heroku/deci/internal/connector"
	// "github.com/heroku/deci/internal/storage"
)

// Config holds the server's configuration options.
//
// Multiple servers using the same storage are expected to be configured identically.
type Config struct {
	// Issuer is the URL the issuer is configured under
	Issuer string

	// AuthPrefix is where the AuthorizationHandler is mounted relative to the
	// Issuer. This is returned in the discovery information. It should have a
	// leading /. Defaults to "/auth"
	AuthPrefix string

	// The backing persistence layer.
	// Storage storage.Storage

	// Connector will be used for session refreshes if it's a connector.RefreshConnector
	// Connector connector.Connector

	// Valid values are "code" to enable the code flow and "token" to enable the implicit
	// flow. If no response types are supplied this value defaults to "code".
	SupportedResponseTypes []string

	// List of allowed origins for CORS requests on discovery, token and keys endpoint.
	// If none are indicated, CORS requests are disabled. Passing in "*" will allow any
	// domain.
	AllowedOrigins []string

	RotateKeysAfter  time.Duration // Defaults to 6 hours.
	IDTokensValidFor time.Duration // Defaults to 24 hours

	GCFrequency time.Duration // Defaults to 5 minutes

	// If specified, the server will use this function for determining time.
	now func() time.Time

	Logger logrus.FieldLogger

	PrometheusRegistry *prometheus.Registry
}

func value(val, defaultValue time.Duration) time.Duration {
	if val == 0 {
		return defaultValue
	}
	return val
}

// Server is the top level object.
type Server struct {
	issuerURL              url.URL
	authPrefix             string
	storage                idp.Storage
	connector              idp.Connector
	supportedResponseTypes map[string]bool
	idTokensValidFor       time.Duration
	allowedOrigins         []string
	prometheusRegistry     *prometheus.Registry
	logger                 logrus.FieldLogger

	now func() time.Time
}

// NewServer constructs a server from the provided config, and authorization
// handler.
func NewServer(ctx context.Context, c *Config) (*Server, error) {
	return newServer(ctx, c, defaultRotationStrategy(
		value(c.RotateKeysAfter, 6*time.Hour),
		value(c.IDTokensValidFor, 24*time.Hour),
	))
}

func newServer(ctx context.Context, c *Config) (*Server, error) {
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	authPrefix := c.AuthPrefix
	if authPrefix == "" {
		authPrefix = "/auth"
	}

	if c.Storage == nil {
		return nil, errors.New("server: storage cannot be nil")
	}
	if len(c.SupportedResponseTypes) == 0 {
		c.SupportedResponseTypes = []string{responseTypeCode}
	}

	supported := make(map[string]bool)
	for _, respType := range c.SupportedResponseTypes {
		switch respType {
		case responseTypeCode, responseTypeIDToken, responseTypeToken:
		default:
			return nil, fmt.Errorf("unsupported response_type %q", respType)
		}
		supported[respType] = true
	}

	now := c.now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		issuerURL:              *issuerURL,
		authPrefix:             authPrefix,
		storage:                newKeyCacher(c.Storage, now),
		supportedResponseTypes: supported,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		now:                    now,
		logger:                 c.Logger,
		connector:              c.Connector,
		prometheusRegistry:     c.PrometheusRegistry,
	}

	s.startKeyRotation(ctx, rotationStrategy, now)
	s.startGarbageCollection(ctx, value(c.GCFrequency, 5*time.Minute), now)

	return s, nil
}

// Mount attaches the HTTP paths to the given router. The prefix (if any) is
// determined from the issuer.
func (s *Server) Mount(r *mux.Router) error {
	requestCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Count of all HTTP requests.",
	}, []string{"handler", "code", "method"})

	err := s.prometheusRegistry.Register(requestCounter)
	if err != nil {
		return fmt.Errorf("server: Failed to register Prometheus HTTP metrics: %v", err)
	}

	instrumentHandlerCounter := func(handlerName string, handler http.Handler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := httpsnoop.CaptureMetrics(handler, w, r)
			requestCounter.With(prometheus.Labels{"handler": handlerName, "code": strconv.Itoa(m.Code), "method": r.Method}).Inc()
		})
	}

	handleFunc := func(p string, h http.HandlerFunc) {
		r.HandleFunc(path.Join(s.issuerURL.Path, p), instrumentHandlerCounter(p, h))
	}
	handleWithCORS := func(p string, h http.HandlerFunc) {
		var handler http.Handler = h
		if len(s.allowedOrigins) > 0 {
			corsOption := handlers.AllowedOrigins(s.allowedOrigins)
			handler = handlers.CORS(corsOption)(handler)
		}
		r.Handle(path.Join(s.issuerURL.Path, p), handler)
	}
	r.NotFoundHandler = http.HandlerFunc(http.NotFound)

	discoveryHandler, err := s.discoveryHandler()
	if err != nil {
		return err
	}
	handleWithCORS("/.well-known/openid-configuration", discoveryHandler)

	// TODO(ericchiang): rate limit certain paths based on IP.
	handleWithCORS("/token", s.handleToken)
	handleWithCORS("/token", s.handleToken)
	handleWithCORS("/keys", s.handlePublicKeys)
	handleFunc("/approval", s.handleApproval)

	return nil
}

// Healthy checks the underlying state of the server, returning nil if it is
// expected to be fine or an error reflecting why it is not.
func (s *Server) Healthy() error {
	// Instead of trying to introspect health, just try to use the underlying storage.
	a := storage.AuthRequest{
		ID:       storage.NewID(),
		ClientID: storage.NewID(),

		// Set a short expiry so if the delete fails this will be cleaned up quickly by garbage collection.
		Expiry: s.now().Add(time.Minute),
	}

	if err := s.storage.CreateAuthRequest(a); err != nil {
		return fmt.Errorf("create auth request: %v", err)
	}
	if err := s.storage.DeleteAuthRequest(a.ID); err != nil {
		return fmt.Errorf("delete auth request: %v", err)
	}
	return nil
}

func (s *Server) absPath(pathItems ...string) string {
	paths := make([]string, len(pathItems)+1)
	paths[0] = s.issuerURL.Path
	copy(paths[1:], pathItems)
	return path.Join(paths...)
}

func (s *Server) absURL(pathItems ...string) string {
	u := s.issuerURL
	u.Path = s.absPath(pathItems...)
	return u.String()
}

func (s *Server) CallbackURL() string {
	return s.absURL("/callback")
}
