package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/justinas/nosurf"
	oidcm "github.com/lstoll/oidc/middleware"
)

type WebauthnUserStore interface {
	GetUserByID(ctx context.Context, id string, allowInactive bool) (*WebauthnUser, bool, error)
	GetUserByEmail(ctx context.Context, email string) (*WebauthnUser, bool, error)
	CreateUser(ctx context.Context, u *WebauthnUser) (id string, err error)
	UpdateUser(ctx context.Context, u *WebauthnUser) error
	UpdateCredential(ctx context.Context, userID string, cred webauthn.Credential) error
	// AddCredentialToUser adds the credential to the user, returning the
	// friendly ID
	AddCredentialToUser(ctx context.Context, userid string, credential webauthn.Credential, keyName string) (id string, err error)
	// DeleteCredentialFromuser takes the friendly ID for the credential
	DeleteCredentialFromuser(ctx context.Context, userid string, credentialID string) error
	ListUsers(ctx context.Context) ([]*WebauthnUser, error)
	DeleteUser(ctx context.Context, id string) error
}

type webauthnManager struct {
	store    WebauthnUserStore
	webauthn *webauthn.WebAuthn

	// oidcMiddleware is used to gate access to the system. It should be
	// configured with the right ACR.
	oidcMiddleware *oidcm.Handler
	csrfMiddleware func(http.Handler) http.Handler

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
	mux.Handle("/users", w.oidcMiddleware.Wrap(w.csrfMiddleware(http.HandlerFunc(w.users))))
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

	responded, overridden, u := w.userForReq(rw, req)
	if responded {
		return
	}

	if req.Method == http.MethodPost {
		switch req.Form.Get("action") {
		case "delete":
			if err := w.deleteKey(req.Context(), u, req.Form); err != nil {
				w.httpErr(req.Context(), rw, err)
				return
			}
		case "registerKey":
			sess := sessionFromContext(req.Context())
			sess.PendingWebauthnEnrollment = &pendingWebauthnEnrollment{
				ForUserID: u.ID,
				ReturnTo:  "/authenticators",
			}
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
		waq = fmt.Sprintf("override_uid=" + u.ID)
	}

	w.execTemplate(rw, req, "list_keys.tmpl.html", map[string]interface{}{
		"User":          u,
		"WebauthnQuery": waq,
	})
}

func (w *webauthnManager) deleteKey(ctx context.Context, u *WebauthnUser, form url.Values) error {
	id := form.Get("keyID")
	if id == "" {
		// TODO - more elegant
		return fmt.Errorf("keyID not provided")
	}

	return w.store.DeleteCredentialFromuser(ctx, u.ID, id)
}

// users is an admin that lists users, allowing for them to be added, deleted etc.
func (w *webauthnManager) users(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		http.Error(rw, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	claims := oidcm.ClaimsFromContext(req.Context())
	if claims == nil {
		w.httpUnauth(rw, "")
		return
	}
	if !w.isAdmin(claims.Subject) {
		w.httpUnauth(rw, "not an admin")
		return
	}

	if req.Method == http.MethodPost {
		switch req.Form.Get("action") {
		case "create":
			if err := w.addUser(req.Context(), req.Form); err != nil {
				w.httpErr(req.Context(), rw, err)
				return
			}
		case "delete":
			if err := w.deleteUser(req.Context(), req.Form); err != nil {
				w.httpErr(req.Context(), rw, err)
				return
			}
		default:
			w.httpErr(req.Context(), rw, fmt.Errorf("unknown action %s", req.Form.Get("action")))
			return
		}
		http.Redirect(rw, req, req.URL.Path, http.StatusSeeOther)
		return
	}

	users, err := w.store.ListUsers(req.Context())
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	w.execTemplate(rw, req, "admin_users.tmpl.html", map[string]interface{}{"Users": users})
}

// addUser handles POSTS to the user page, to create a user
func (w *webauthnManager) addUser(ctx context.Context, form url.Values) error {
	u := WebauthnUser{
		Email:     form.Get("email"),
		FullName:  form.Get("fullName"),
		Activated: true, // always for direct creation. TODO - UI for enrollment?
	}
	if u.Email == "" || u.FullName == "" {
		// TODO - more elegant than a 500
		return fmt.Errorf("email and full name must be specified")
	}
	if _, err := w.store.CreateUser(ctx, &u); err != nil { // always active immediately in UI
		return err
	}
	return nil
}

// deleteUser handles DELETEs to the user page, to remove a user
func (w *webauthnManager) deleteUser(ctx context.Context, form url.Values) error {
	id := form.Get("userID")
	if id == "" {
		// TODO - more elegant
		return fmt.Errorf("userID not provided")
	}
	return w.store.DeleteUser(ctx, id)
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
		u, ok, err := w.store.GetUserByID(req.Context(), uid, true)
		if err != nil {
			w.httpErr(req.Context(), rw, fmt.Errorf("getting user %s: %w", uid, err))
			return
		}
		if !ok {
			w.httpNotFound(rw)
			return
		}
		if u.Activated || subtle.ConstantTimeCompare([]byte(et), []byte(u.EnrollmentKey)) == 0 {
			w.httpUnauth(rw, "invalid enrollment")
			return
		}
		ss := sessionFromContext(req.Context())
		ss.PendingWebauthnEnrollment = &pendingWebauthnEnrollment{
			ForUserID: uid,
		}
	}
	// list keys will send the pending enrollment ID

	w.execTemplate(rw, req, "register_key.tmpl.html", map[string]interface{}{})
}

func (w *webauthnManager) beginRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := sessionFromContext(req.Context())

	if sess.PendingWebauthnEnrollment == nil || sess.PendingWebauthnEnrollment.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	u, ok, err := w.store.GetUserByID(req.Context(), sess.PendingWebauthnEnrollment.ForUserID, true)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("getting user %s: %w", sess.PendingWebauthnEnrollment.ForUserID, err))
		return
	}
	if !ok {
		w.httpNotFound(rw)
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

	options, sessionData, err := w.webauthn.BeginRegistration(u, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	sess.PendingWebauthnEnrollment.KeyName = keyName
	sess.PendingWebauthnEnrollment.WebauthnSessionData = sessionData

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
}

func (w *webauthnManager) finishRegistration(rw http.ResponseWriter, req *http.Request) {
	sess := sessionFromContext(req.Context())

	if sess.PendingWebauthnEnrollment == nil || sess.PendingWebauthnEnrollment.ForUserID == "" {
		w.httpUnauth(rw, "no enroll to user id set in session")
		return
	}

	u, ok, err := w.store.GetUserByID(req.Context(), sess.PendingWebauthnEnrollment.ForUserID, true) // TODO - guard the allow unactive for enrol only!
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("getting user %s: %w", sess.PendingWebauthnEnrollment.ForUserID, err))
		return
	}
	if !ok {
		w.httpNotFound(rw)
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

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(req.Body)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("parsing credential creation response: %w", err))
		return
	}
	credential, err := w.webauthn.CreateCredential(u, sessionData, parsedResponse)
	if err != nil {
		w.httpErr(req.Context(), rw, fmt.Errorf("creating credential: %w", err))
		return
	}

	if _, err := w.store.AddCredentialToUser(req.Context(), u.ID, *credential, keyName); err != nil {
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
func (w *webauthnManager) userForReq(rw http.ResponseWriter, req *http.Request) (responded, overridden bool, u *WebauthnUser) {
	overridden = false

	claims := oidcm.ClaimsFromContext(req.Context())
	if claims == nil {
		w.httpUnauth(rw, "")
		return true, overridden, nil
	}

	uid := claims.Subject
	if req.URL.Query().Get("override_uid") != "" && w.isAdmin(claims.Subject) {
		// impersonation path = we allow user to override the user ID to perform
		// actions as the targeted user
		uid = req.URL.Query().Get("override_uid")
		overridden = true
	}

	u, ok, err := w.store.GetUserByID(req.Context(), uid, false)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return true, overridden, nil
	}
	if !ok {
		w.httpNotFound(rw)
		return true, overridden, nil
	}

	return false, overridden, u
}

func (w *webauthnManager) httpErr(ctx context.Context, rw http.ResponseWriter, err error) {
	log.Printf("error %#v", err)
	l := ctxLog(ctx)
	var pErr *protocol.Error
	if errors.As(err, &pErr) {
		if pErr.DevInfo != "" {
			l = l.WithField("webauthnDevInfo", pErr.DevInfo)
		}
	}
	l.Error(err)
	http.Error(rw, "Internal Error", http.StatusInternalServerError)
}

func (w *webauthnManager) httpUnauth(rw http.ResponseWriter, msg string) {
	http.Error(rw, fmt.Sprintf("Access denied: %s", msg), http.StatusForbidden)
}

func (w *webauthnManager) httpNotFound(rw http.ResponseWriter) {
	http.Error(rw, "Not Found", http.StatusNotFound)
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
		"pathFor": func(s string) string {
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
