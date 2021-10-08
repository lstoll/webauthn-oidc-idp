//go:build notatall

package webauthn

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/koesie10/webauthn/protocol"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/koesie10/webauthn/webauthn"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	"github.com/lstoll/idp/session"
	"github.com/lstoll/idp/webauthn/webauthnpb"
	"github.com/tjarratt/babble"
)

var _ idp.Connector = (*Connector)(nil)

const (
	authMethodKey = "sso-method"
	authIDKey     = "authID"
	usernameKey   = "username"
)

// Connector is a basic user/pass connector with in-memory credentials
type Connector struct {
	Logger logrus.FieldLogger
	// Users maps user -> password
	Users map[string]string
	// Authenticator to deal with
	Authenticators map[idp.SSOMethod]idp.Authenticator
	// WebAuthn helper
	WebAuthn *webauthn.WebAuthn
	// How we manage users
	UserAuthenticator webauthnpb.WebAuthnUserServiceClient

	words babble.Babbler
}

func NewConnector(l logrus.FieldLogger, ua webauthnpb.WebAuthnUserServiceClient) (*Connector, error) {
	w, err := webauthn.New(&webauthn.Config{
		AuthenticatorStore: &storage{ua: ua},
		RelyingPartyName:   "idp",
		// TODO RelyingPartyID
	})
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing webauthn helper")
	}

	b := babble.NewBabbler()
	b.Count = 4
	b.Separator = " "

	return &Connector{
		Logger:            l,
		WebAuthn:          w,
		UserAuthenticator: ua,
		words:             b,
	}, nil
}

func (c *Connector) Initialize(method idp.SSOMethod, auth idp.Authenticator) error {
	if c.Authenticators == nil {
		c.Authenticators = map[idp.SSOMethod]idp.Authenticator{}
	}
	c.Authenticators[method] = auth
	return nil
}

var indexTemplate = template.Must(template.New("index.html").Parse(string(MustAsset("webauthn/webauthn.tmpl.html"))))

// LoginPage is the handler the IDP calls to kick off the login flow.
func (c *Connector) LoginPage(w http.ResponseWriter, r *http.Request, lr idp.LoginRequest) {
	sess := session.FromContext(r.Context())
	sess.Values[authIDKey] = lr.AuthID
	sess.Values[authMethodKey] = lr.SSOMethod
	var sessUser string
	if su, ok := sess.Values[usernameKey]; ok {
		sessUser = su.(string)
	}

	if err := indexTemplate.Execute(w, struct {
		Username string
	}{
		Username: sessUser,
	}); err != nil {
		c.Logger.WithError(err).Error("Failed to render index")
		http.Error(w, "Failed to render index", http.StatusInternalServerError)
		return
	}
}

type loginBody struct {
	Username string `json:"username"`
}

func (c *Connector) LoginStart(w http.ResponseWriter, r *http.Request) {
	sess := webauthn.WrapMap(session.FromContext(r.Context()).Values)

	lb := registrationBody{}
	if err := json.NewDecoder(r.Body).Decode(&lb); err != nil {
		c.Logger.WithError(err).Error("Failed to parse login start body")
		http.Error(w, "Failed to parse login start body", http.StatusInternalServerError)
		return
	}

	// Look up user.
	ureq := &webauthnpb.GetUserRequest{Username: lb.Username}
	uresp, err := c.UserAuthenticator.GetUser(r.Context(), ureq)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			http.Error(w, "Invalid user", http.StatusForbidden)
			return
		}
		c.Logger.WithError(err).Error("Failed to look up user")
		http.Error(w, "Error looking up user", http.StatusInternalServerError)
		return
	}

	// Reset the userID in use
	delete(session.FromContext(r.Context()).Values, usernameKey)
	session.FromContext(r.Context()).Values[usernameKey] = uresp.User.Username
	log.Printf("++ user %#v", uresp.User)
	options, err := c.WebAuthn.GetLoginOptions(&user{WebauthnUser: uresp.User}, sess)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get login options")
		http.Error(w, "Failed to setup login options", http.StatusInternalServerError)
		return
	}
	// We permit this as a single factor login, so make sure the user is present
	options.PublicKey.UserVerification = protocol.UserVerificationRequired

	if err := json.NewEncoder(w).Encode(options); err != nil {
		c.Logger.WithError(err).Error("Failed to marshal options")
		http.Error(w, "Failed to marshal options", http.StatusInternalServerError)
		return
	}
}

type loginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

func (c *Connector) LoginFinish(w http.ResponseWriter, r *http.Request) {
	sess := webauthn.WrapMap(session.FromContext(r.Context()).Values)

	userID := session.FromContext(r.Context()).Values[usernameKey]
	ureq := &webauthnpb.GetUserRequest{Username: userID.(string)}
	uresp, err := c.UserAuthenticator.GetUser(r.Context(), ureq)
	if err != nil {
		delete(session.FromContext(r.Context()).Values, usernameKey)
		c.Logger.WithError(err).Error("Error fetching user")
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	// This will make sure the user we expect owns this authenticator. If we get past this point, we know
	// dbuser is correct.
	auth := c.WebAuthn.FinishLogin(r, w, &user{WebauthnUser: uresp.User}, sess)
	if auth == nil {
		// the finish handler deals with the http stuff, so bail
		return
	}

	uauth, err := c.UserAuthenticator.GetAuthenticator(r.Context(), &webauthnpb.GetAuthenticatorRequest{AuthenticatorId: auth.WebAuthID()})
	if err != nil {
		c.Logger.WithError(err).Error("Error re-fetching authenticator")
		http.Error(w, "Error finishing login", http.StatusInternalServerError)
		return
	}

	if !uauth.Authenticator.Active {
		http.Error(w, "Authenticator not active", http.StatusForbidden)
		return
	}

	//  Call the authenticate method, then marshal the response URL into the
	//  response JSON. The client can then send the user there and we're done.

	ssom := session.FromContext(r.Context()).Values[authMethodKey]
	ssoauth, ok := c.Authenticators[ssom.(idp.SSOMethod)]
	if !ok {
		c.Logger.WithError(err).Error("Invalid SSO method")
		http.Error(w, "Invalid SSO method", http.StatusBadRequest)
		return
	}

	redir, err := ssoauth.Authenticate(session.FromContext(r.Context()).Values[authIDKey].(string), idppb.Identity{UserId: uresp.User.Username})
	if err != nil {
		c.Logger.WithError(err).Error("Error fetching user")
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	lr := loginResponse{RedirectTo: redir}

	if err := json.NewEncoder(w).Encode(&lr); err != nil {
		c.Logger.WithError(err).Error("Error sending response")
		http.Error(w, "Error sending response", http.StatusInternalServerError)
		return
	}
}

type registrationBody struct {
	Username string `json:"username"`
}

func (c *Connector) RegistrationStart(w http.ResponseWriter, r *http.Request) {
	sess := webauthn.WrapMap(session.FromContext(r.Context()).Values)

	// Clear the UserID Tracking
	delete(session.FromContext(r.Context()).Values, usernameKey)

	rb := registrationBody{}
	if err := json.NewDecoder(r.Body).Decode(&rb); err != nil {
		c.Logger.WithError(err).Error("Failed to parse registration start body")
		http.Error(w, "Failed to parse registration start body", http.StatusInternalServerError)
		return
	}
	if rb.Username == "" {
		http.Error(w, "Username not present", http.StatusBadRequest)
		return
	}

	session.FromContext(r.Context()).Values[usernameKey] = rb.Username

	// TODO - better user object for this? This is a hack to have enough to
	// satify the form, but it'd be nicer to make that more explicit
	regUsr := &user{WebauthnUser: &webauthnpb.WebauthnUser{Username: rb.Username}}
	options, err := c.WebAuthn.GetRegistrationOptions(regUsr, sess)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get registration options")
		http.Error(w, "Failed to setup registration options", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(options); err != nil {
		c.Logger.WithError(err).Error("Failed to marshal options")
		http.Error(w, "Failed to marshal options", http.StatusInternalServerError)
		return
	}
}

func (c *Connector) RegistrationFinish(w http.ResponseWriter, r *http.Request) {
	sess := webauthn.WrapMap(session.FromContext(r.Context()).Values)

	userID, ok := session.FromContext(r.Context()).Values[usernameKey]
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusBadRequest)
		return
	}
	delete(session.FromContext(r.Context()).Values, usernameKey)

	ureq := &webauthnpb.GetUserRequest{Username: userID.(string)}
	uresp, err := c.UserAuthenticator.GetUser(r.Context(), ureq)
	if err != nil && status.Code(err) != codes.NotFound {
		c.Logger.WithError(err).Error("Failed to get user")
		http.Error(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	var attestationResponse protocol.AttestationResponse
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&attestationResponse); err != nil {
		c.Logger.WithError(err).Error("Failed to marshal options")
		http.Error(w, "Failed to marshal options", http.StatusInternalServerError)
		return
	}

	// Generate challenge
	challenge := c.words.Babble()

	// Check if the user exists. If they do, parse and finish registration, and
	// attach the challenge to the authenticator. If not, skip it so we don't
	// leak usernames

	if uresp != nil && uresp.User != nil {
		// This will also associate the user to the authenticator in the store.
		auth, err := c.WebAuthn.ParseAndFinishRegistration(attestationResponse, &user{WebauthnUser: uresp.User}, sess)
		if err != nil {
			if err, ok := err.(*protocol.Error); ok {
				c.Logger.WithError(err).Errorf("Failed to finish registration: %s", err.Debug)
			} else {
				c.Logger.WithError(err).Error("Failed to finish registration")
			}
			http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
			return
		}

		sauth, err := c.UserAuthenticator.GetAuthenticator(r.Context(), &webauthnpb.GetAuthenticatorRequest{AuthenticatorId: auth.WebAuthID()})
		if err != nil {
			c.Logger.WithError(err).Error("Failed to re-fetch authenticator")
			http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
			return
		}

		sauth.Authenticator.ActivationChallenge = challenge

		if _, err := c.UserAuthenticator.UpdateAuthenticator(r.Context(), &webauthnpb.UpdateAuthenticatorRequest{Authenticator: sauth.Authenticator}); err != nil {
			c.Logger.WithError(err).Error("Failed to update authenticator")
			http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
			return

		}
	}

	resp := struct {
		Challenge string `json:"challenge"`
	}{
		Challenge: challenge,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		c.Logger.WithError(err).Error("Failed to marshal response")
		http.Error(w, "Failed to marshal options", http.StatusInternalServerError)
		return
	}
}

// MountRoutes mounts the dex and connector HTTP routes on the given chi mux
func (c *Connector) MountRoutes(mux *chi.Mux) {
	mux.Get("/webauthn.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write(MustAsset("webauthn/webauthn.js"))
	})
	mux.Post("/webauthn/registration/start", c.RegistrationStart)
	mux.Post("/webauthn/registration/finish", c.RegistrationFinish)
	mux.Post("/webauthn/login/start", c.LoginStart)
	mux.Post("/webauthn/login/finish", c.LoginFinish)
}
