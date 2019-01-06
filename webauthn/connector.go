package webauthn

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/koesie10/webauthn/protocol"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/koesie10/webauthn/webauthn"
	"github.com/lstoll/idp"
	"github.com/lstoll/idp/idppb"
	"github.com/lstoll/idp/session"
)

var _ idp.Connector = (*Connector)(nil)

const (
	userIDKey   = "user-id"
	authIDKey   = "authID"
	usernameKey = "username"
)

// Connector is a basic user/pass connector with in-memory credentials
type Connector struct {
	Logger logrus.FieldLogger
	// Users maps user -> password
	Users map[string]string
	// Authenticator to deal with
	Authenticator idp.Authenticator
	// WebAuthn helper
	WebAuthn *webauthn.WebAuthn
	// How we manage users
	UserAuthenticator UserAuthenticator
}

func NewConnector(l logrus.FieldLogger, ua UserAuthenticator) (*Connector, error) {
	w, err := webauthn.New(&webauthn.Config{
		AuthenticatorStore: &storage{ua: ua},
		RelyingPartyName:   "idp",
		// TODO RelyingPartyID
	})
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing webauthn helper")
	}

	return &Connector{
		Logger:            l,
		WebAuthn:          w,
		UserAuthenticator: ua,
	}, nil
}

func (c *Connector) Initialize(auth idp.Authenticator) error {
	c.Authenticator = auth
	return nil
}

var indexTemplate = template.Must(template.New("index.html").Parse(string(MustAsset("webauthn/webauthn.tmpl.html"))))

// LoginPage is the handler the IDP calls to kick off the login flow.
func (c *Connector) LoginPage(w http.ResponseWriter, r *http.Request, lr idp.LoginRequest) {
	sess := session.FromContext(r.Context())
	sess.Values[authIDKey] = lr.AuthID
	var sessUser string
	if su, ok := sess.Values[usernameKey]; ok {
		sessUser = su.(string)
	}

	// TODO - store the ID in session, not the login name.
	// send this to a hidden field on the form
	// trigged the auto login based on the hidden field
	// make the login finish look for this hidden field, and if it
	// does log this user in based on the session value (don't trust user submitted).
	// if not, look for username and look the user up by that.

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

	//sessUser, _ := sess.Values[usernameKey]

	options, err := c.WebAuthn.GetLoginOptions(nil, sess)
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

	auth := c.WebAuthn.FinishLogin(r, w, nil, sess)
	if auth == nil {
		// the finish handler deals with the http stuff, so bail
		return
	}

	dbauth, err := c.UserAuthenticator.GetAuthenticator(auth.WebAuthID())
	if err != nil {
		c.Logger.WithError(err).Error("Error fetching authenticator")
		http.Error(w, "Error fetching authenticator", http.StatusInternalServerError)
		return
	}

	dbuser, err := c.UserAuthenticator.GetUser(dbauth.UserId)
	if err != nil {
		c.Logger.WithError(err).Error("Error fetching user")
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	// At this point we're left with the authenticator details. Look up the user
	// information from the key to work out who we are. Call the authenticate
	// method, then marshal the response URL into the response JSON. The client
	// can then send the user there and we're done.

	redir, err := c.Authenticator.Authenticate(session.FromContext(r.Context()).Values[authIDKey].(string), idppb.Identity{UserId: dbuser.Id})
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
	Password string `json:"password"`
}

func (c *Connector) RegistrationStart(w http.ResponseWriter, r *http.Request) {
	sess := webauthn.WrapMap(session.FromContext(r.Context()).Values)

	// Clear the UserID Tracking
	delete(session.FromContext(r.Context()).Values, userIDKey)

	rb := registrationBody{}
	if err := json.NewDecoder(r.Body).Decode(&rb); err != nil {
		c.Logger.WithError(err).Error("Failed to parse registration start body")
		http.Error(w, "Failed to parse registration start body", http.StatusInternalServerError)
		return
	}

	lu, err := c.UserAuthenticator.LoginUser(rb.Username, rb.Password)
	if err != nil {
		c.Logger.WithError(err).Error("Error logging user in")
		// Assume access denied for now, we don't differ error vs. not allowed
		http.Error(w, "Failed to parse registration start body", http.StatusForbidden)
		return
	}

	session.FromContext(r.Context()).Values[userIDKey] = lu.Id

	options, err := c.WebAuthn.GetRegistrationOptions(&user{WebauthnUser: lu}, sess)
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

	userID, ok := session.FromContext(r.Context()).Values[userIDKey]
	if !ok {
		http.Error(w, "User ID not found in session", http.StatusBadRequest)
		return
	}

	lu, err := c.UserAuthenticator.GetUser(userID.(string))
	if err != nil {
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

	// This will also associate the user to the authenticator in the store.
	_, err = c.WebAuthn.ParseAndFinishRegistration(attestationResponse, &user{WebauthnUser: lu}, sess)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to finish registration")
		http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
		return
	}

	// Caller page should re-prompt for login at this point.
	w.WriteHeader(http.StatusCreated)
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
