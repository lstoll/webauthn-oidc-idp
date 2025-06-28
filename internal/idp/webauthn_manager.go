package idp

import (
	"context"
	"crypto/subtle"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/justinas/nosurf"
	"github.com/lstoll/web"
	"github.com/lstoll/web/session"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	webcontent "github.com/lstoll/webauthn-oidc-idp/web"
)

func init() {
	gob.Register(&pendingWebauthnEnrollment{})
	gob.Register(&webauthnLoginData{})
}

const pendingWebauthnEnrollmentSessionKey = "pending_webauthn_enrollment"

// pendingWebauthnEnrollment tracks enrollment info across an authenticator
// registration.
type pendingWebauthnEnrollment struct {
	ForUserID           string                `json:"for_user_id,omitempty"`
	KeyName             string                `json:"key_name,omitempty"`
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// ReturnTo redirects the user here after the key is registered.
	ReturnTo string `json:"return_to,omitempty"`
}

const webauthnLoginDataSessionKey = "webauthn_login"

// webauthnLogin tracks data for a login session
type webauthnLoginData struct {
	// LoginSessionID is the current OIDC session ID for the flow
	LoginSessionID string `json:"login_session_id"`
	// WebauthnSessionData is the data for the in-process login
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// AuthdUser tracks information about the user we just authenticated, for
	// when we send the user to the login finished page.
	AuthdUser *webauthnLogin `json:"authd_user,omitempty"`
}

type webauthnLogin struct {
	UserID      string
	ValidBefore time.Time
	SessionID   string
}

type webSession struct {
	PendingWebauthnEnrollment *pendingWebauthnEnrollment `json:"pending_webauthn_enrollment,omitempty"`
	WebauthnLogin             *webauthnLoginData         `json:"webauthn_login,omitempty"`
}

type webauthnManager struct {
	db       *DB
	queries  *queries.Queries
	webauthn *webauthn.WebAuthn
}

func (w *webauthnManager) AddHandlers(websvr *web.Server) {
	websvr.HandleFunc("/registration/begin", w.beginRegistration)
	websvr.HandleFunc("/registration/finish", w.finishRegistration)
	websvr.HandleFunc("GET /registration", w.registration)
}

// registration is a page used to add a new key. It should handle either a user
// in the session (from the logged in keys page), or a boostrap token and user
// id as query params for an inactive user.
func (w *webauthnManager) registration(rw http.ResponseWriter, req *http.Request) {
	// first, check the URL for a registration token and user id. If it exists,
	// check if we have the user and if they are active/with a matching token,
	// embed it in the page.
	uid := req.URL.Query().Get("user_id")
	et := req.URL.Query().Get("enrollment_token")
	if uid != "" && et != "" {
		// we want to enroll a user. Find them, and match the token
		user, err := w.queries.GetUser(req.Context(), uuid.MustParse(uid))
		if err != nil {
			w.httpErr(req.Context(), rw, fmt.Errorf("get user %s: %w", uid, err))
			return
		}
		if !user.EnrollmentKey.Valid || user.EnrollmentKey.String == "" || subtle.ConstantTimeCompare([]byte(et), []byte(user.EnrollmentKey.String)) == 0 {
			w.httpUnauth(rw, "either previous enrollment completed fine, or invalid enrollment")
			return
		}
		sess := session.MustFromContext(req.Context())
		sess.Set(pendingWebauthnEnrollmentSessionKey, &pendingWebauthnEnrollment{
			ForUserID: uid,
		})
		log.Printf("set pendingWebauthnEnrollmentSessionKey: %#v", sess)
	}
	// list keys will send the pending enrollment ID

	w.execTemplate(rw, req, "register_key.tmpl.html", map[string]interface{}{})
}

func (w *webauthnManager) beginRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := session.MustFromContext(req.Context())

	log.Printf("beginRegistration: %#v", sess)

	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	user, err := w.queries.GetUser(req.Context(), uuid.MustParse(pwe.ForUserID))
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("get user %s: %w", pwe.ForUserID, err))
		return
	}

	// postttttt this
	keyName := req.URL.Query().Get("key_name")
	if keyName == "" {
		w.httpErr(req.Context(), rw, fmt.Errorf("key name required"))
		return
	}

	authSelect := protocol.AuthenticatorSelection{
		RequireResidentKey: protocol.ResidentKeyRequired(),
		UserVerification:   protocol.VerificationRequired,
	}
	conveyancePref := protocol.ConveyancePreference(protocol.PreferDirectAttestation)

	options, sessionData, err := w.webauthn.BeginRegistration(&webauthnUser{qu: user}, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	pwe.KeyName = keyName
	pwe.WebauthnSessionData = sessionData
	sess.Set(pendingWebauthnEnrollmentSessionKey, pwe)

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
}

func (w *webauthnManager) finishRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := session.MustFromContext(req.Context())

	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	user, err := w.queries.GetUser(req.Context(), uuid.MustParse(pwe.ForUserID)) // TODO - guard the allow unactive for enrol only!
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("getting user %s: %w", pwe.ForUserID, err))
		return
	}

	if pwe.WebauthnSessionData == nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("session data not in session"))
		return
	}
	sessionData := *pwe.WebauthnSessionData
	keyName := pwe.KeyName

	// purge the data from the session
	returnTo := pwe.ReturnTo
	sess.Set(pendingWebauthnEnrollmentSessionKey, nil)

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(req.Body)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("parsing credential creation response: %w", err))
		return
	}
	credential, err := w.webauthn.CreateCredential(&webauthnUser{qu: user}, sessionData, parsedResponse)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("creating credential: %w", err))
		return
	}

	cb, err := json.Marshal(credential)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("marshalling credential: %w", err))
		return
	}

	if err := w.queries.CreateUserCredential(req.Context(), queries.CreateUserCredentialParams{
		UserID:         user.ID,
		CredentialID:   credential.ID,
		CredentialData: cb,
		Name:           keyName,
	}); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	// OK
	_ = returnTo
	// TODO - return the next URL in the response, make the JS follow it.
}

func (w *webauthnManager) httpErr(ctx context.Context, rw http.ResponseWriter, err error) {
	var (
		pErr    *protocol.Error
		devinfo string
	)
	if errors.As(err, &pErr) {
		devinfo = pErr.DevInfo
	}
	if errors.Is(err, ErrUserNotFound) || errors.Is(err, ErrUserNotActivated) {
		http.Error(rw, err.Error(), http.StatusNotFound)
	} else {
		slog.ErrorContext(ctx, "webauthn manager error", "err", err, "dev-info", devinfo)
		http.Error(rw, "Internal Error", http.StatusInternalServerError)
	}
}

func (w *webauthnManager) httpUnauth(rw http.ResponseWriter, msg string) {
	http.Error(rw, fmt.Sprintf("Access denied: %s", msg), http.StatusForbidden)
}

func (w *webauthnManager) execTemplate(rw http.ResponseWriter, r *http.Request, templateName string, data interface{}) {
	funcs := template.FuncMap{
		"csrfField": func() template.HTML {
			return template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, nosurf.Token(r)))
		},
		"pathFor": func(_ string) string {
			return "TODO"
		},
	}

	lt, err := template.New("").Funcs(funcs).ParseFS(webcontent.Templates, "templates/webauthn/layout.tmpl.html")
	if err != nil {
		w.httpErr(r.Context(), rw, err)
	}
	t, err := lt.ParseFS(webcontent.Templates, "templates/webauthn/"+templateName)
	if err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
	if err := t.ExecuteTemplate(rw, templateName, data); err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
}
