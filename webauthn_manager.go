package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/justinas/nosurf"
	"github.com/lstoll/cookiesession"
	oidcm "github.com/lstoll/oidc/middleware"
)

type webauthnManager struct {
	db       *DB
	webauthn *webauthn.WebAuthn

	// oidcMiddleware is used to gate access to the system. It should be
	// configured with the right ACR.
	oidcMiddleware *oidcm.Handler
	csrfMiddleware func(http.Handler) http.Handler

	sessmgr *cookiesession.Manager[webSession, *webSession]

	// admins is a list of subjects for users who are administrators. They can
	// list, and add users to the system.
	admins []string
	// acrs is a list of ACR values to request and require for access to the
	// webauthn manager. This will usually be the webauthn ACRs in use, to
	// provide like-for-like access. When bootstrapping the system this should
	// be empty, to allow a federated user to log in.
	acrs []string
}

func (w *webauthnManager) AddHandlers(mux *http.ServeMux) {
	mux.Handle("/authenticators", w.oidcMiddleware.Wrap(w.csrfMiddleware(http.HandlerFunc(w.listKeys))))
	mux.HandleFunc("/registration/begin", w.beginRegistration)
	mux.HandleFunc("/registration/finish", w.finishRegistration)
	mux.HandleFunc("/registration", w.registration)
}

// listKeys is the "index" page for a users credentials. It can be used to add,
func (w *webauthnManager) listKeys(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		http.Error(rw, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	responded, overridden, user := w.userForReq(rw, req)
	if responded {
		return
	}

	if req.Method == http.MethodPost {
		switch req.Form.Get("action") {
		case "delete":
			if err := w.deleteKey(user, req.Form); err != nil {
				w.httpErr(req.Context(), rw, err)
				return
			}
		case "registerKey":
			sess := w.sessmgr.Get(req.Context())
			sess.PendingWebauthnEnrollment = &pendingWebauthnEnrollment{
				ForUserID: user.ID,
				ReturnTo:  "/authenticators",
			}
			w.sessmgr.Save(req.Context(), sess)
			http.Redirect(rw, req, "/registration", http.StatusSeeOther)
		default:
			w.httpErr(req.Context(), rw, fmt.Errorf("unknown action %s", req.Form.Get("action")))
			return
		}
		// TODO - we need to track this some other way, in case form doesn't include it?
		http.Redirect(rw, req, req.URL.Path+"?"+req.URL.Query().Encode(), http.StatusSeeOther)
		return
	}

	// need to propagate this to the JS callbacks. TODO - This is janky,
	// consider putting it in the session or something
	waq := ""
	if overridden {
		waq = fmt.Sprintf("override_uid=" + user.ID)
	}

	w.execTemplate(rw, req, "list_keys.tmpl.html", map[string]interface{}{
		"User":          user,
		"WebauthnQuery": waq,
	})
}

func (w *webauthnManager) deleteKey(user User, form url.Values) error {
	name := form.Get("keyName")
	if name == "" {
		// TODO - more elegant
		return fmt.Errorf("key name not provided")
	}
	return w.db.DeleteUserCredential(user.ID, name)
}

// registration is a page used to add a new key. It should handle either a user
// in the session (from the logged in keys page), or a boostrap token and user
// id as query params for an inactive user.
func (w *webauthnManager) registration(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	// first, check the URL for a registration token and user id. If it exists,
	// check if we have the user and if they are active/with a matching token,
	// embed it in the page.
	uid := req.URL.Query().Get("user_id")
	et := req.URL.Query().Get("enrollment_token")
	if uid != "" && et != "" {
		// we want to enroll a user. Find them, and match the token
		user, err := w.db.GetUserByID(uid)
		if err != nil {
			w.httpErr(req.Context(), rw, fmt.Errorf("get user %s: %w", uid, err))
			return
		}
		if user.Activated || subtle.ConstantTimeCompare([]byte(et), []byte(user.EnrollmentKey)) == 0 {
			w.httpUnauth(rw, "invalid enrollment")
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

	user, err := w.db.GetUserByID(sess.PendingWebauthnEnrollment.ForUserID)
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

	options, sessionData, err := w.webauthn.BeginRegistration(user, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))
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

	user, err := w.db.GetUserByID(sess.PendingWebauthnEnrollment.ForUserID) // TODO - guard the allow unactive for enrol only!
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
	credential, err := w.webauthn.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("creating credential: %w", err))
		return
	}

	if err := w.db.CreateUserCredential(user.ID, keyName, *credential); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	// OK
	_ = returnTo
	// TODO - return the next URL in the response, make the JS follow it.
}

// userForReq gets the user for a given request, accounting for the override_uid
// / admin params. it will handle response to user, indicating if it does via the
// return. If it has, the caller should simply return
func (w *webauthnManager) userForReq(rw http.ResponseWriter, req *http.Request) (responded, overridden bool, user User) {
	overridden = false

	claims := oidcm.ClaimsFromContext(req.Context())
	if claims == nil {
		w.httpUnauth(rw, "")
		return true, overridden, User{}
	}

	uid := claims.Subject
	if req.URL.Query().Get("override_uid") != "" && w.isAdmin(claims.Subject) {
		// impersonation path = we allow user to override the user ID to perform
		// actions as the targeted user
		uid = req.URL.Query().Get("override_uid")
		overridden = true
	}

	user, err := w.db.GetActivatedUserByID(uid)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return true, overridden, User{}
	}

	return false, overridden, user
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
		slog.ErrorContext(ctx, "webauthn manager error", logErr(err), slog.String("dev-info", devinfo))
		http.Error(rw, "Internal Error", http.StatusInternalServerError)
	}
}

func (w *webauthnManager) httpUnauth(rw http.ResponseWriter, msg string) {
	http.Error(rw, fmt.Sprintf("Access denied: %s", msg), http.StatusForbidden)
}

func (w *webauthnManager) isAdmin(sub string) bool {
	for _, a := range w.admins {
		if a == sub {
			return true
		}
	}
	return false
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

	lt, err := template.New("").Funcs(funcs).ParseFS(templates, "web/templates/webauthn/layout.tmpl.html")
	if err != nil {
		w.httpErr(r.Context(), rw, err)
	}
	t, err := lt.ParseFS(templates, "web/templates/webauthn/"+templateName)
	if err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
	if err := t.ExecuteTemplate(rw, templateName, data); err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
}
