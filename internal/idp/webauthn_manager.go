package idp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/justinas/nosurf"
	"github.com/lstoll/cookiesession"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
	"github.com/lstoll/webauthn-oidc-idp/web"
)

type webauthnManager struct {
	db       *DB
	queries  *queries.Queries
	webauthn *webauthn.WebAuthn

	sessmgr *cookiesession.Manager[webSession, *webSession]
}

func (w *webauthnManager) AddHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/registration/begin", w.beginRegistration)
	mux.HandleFunc("/registration/finish", w.finishRegistration)
	mux.HandleFunc("GET /registration", w.registration)
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
		sess := w.sessmgr.Get(req.Context())
		sess.PendingWebauthnEnrollment = &pendingWebauthnEnrollment{
			ForUserID: uid,
		}
		w.sessmgr.Save(req.Context(), sess)
	}
	// list keys will send the pending enrollment ID

	w.execTemplate(rw, req, "register_key.tmpl.html", map[string]interface{}{})
}

func (w *webauthnManager) beginRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := w.sessmgr.Get(req.Context())

	if sess.PendingWebauthnEnrollment == nil || sess.PendingWebauthnEnrollment.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	user, err := w.queries.GetUser(req.Context(), uuid.MustParse(sess.PendingWebauthnEnrollment.ForUserID))
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("get user %s: %w", sess.PendingWebauthnEnrollment.ForUserID, err))
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

	sess.PendingWebauthnEnrollment.KeyName = keyName
	sess.PendingWebauthnEnrollment.WebauthnSessionData = sessionData
	w.sessmgr.Save(req.Context(), sess)

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
}

func (w *webauthnManager) finishRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := w.sessmgr.Get(req.Context())

	if sess.PendingWebauthnEnrollment == nil || sess.PendingWebauthnEnrollment.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	user, err := w.queries.GetUser(req.Context(), uuid.MustParse(sess.PendingWebauthnEnrollment.ForUserID)) // TODO - guard the allow unactive for enrol only!
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("getting user %s: %w", sess.PendingWebauthnEnrollment.ForUserID, err))
		return
	}

	if sess.PendingWebauthnEnrollment.WebauthnSessionData == nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("session data not in session"))
		return
	}
	sessionData := *sess.PendingWebauthnEnrollment.WebauthnSessionData
	keyName := sess.PendingWebauthnEnrollment.KeyName

	// purge the data from the session
	returnTo := sess.PendingWebauthnEnrollment.ReturnTo
	sess.PendingWebauthnEnrollment = nil
	w.sessmgr.Save(req.Context(), sess)

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

	lt, err := template.New("").Funcs(funcs).ParseFS(web.Templates, "templates/webauthn/layout.tmpl.html")
	if err != nil {
		w.httpErr(r.Context(), rw, err)
	}
	t, err := lt.ParseFS(web.Templates, "templates/webauthn/"+templateName)
	if err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
	if err := t.ExecuteTemplate(rw, templateName, data); err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
}
