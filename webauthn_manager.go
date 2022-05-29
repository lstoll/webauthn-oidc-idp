package main

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/csrf"
	oidcm "github.com/pardot/oidc/middleware"
)

const (
	webauthnmgrSessionName = "wamgr"
)

var _ = func() struct{} {
	gob.Register(webauthn.SessionData{})
	return struct{}{}
}()

//go:embed web/templates/webauthn/*
var webauthnTemplateData embed.FS

type WebauthnUserStore interface {
	GetUserByID(ctx context.Context, id string) (*WebauthnUser, bool, error)
	GetUserByEmail(ctx context.Context, email string) (*WebauthnUser, bool, error)
	CreateUser(ctx context.Context, u *WebauthnUser) (id string, err error)
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

	// httpPrefix is the prefix which the service is mounted under, so we can
	// add this to path references we generate
	httpPrefix  string
	handler     http.Handler
	initHandler sync.Once
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

func (w *webauthnManager) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	w.initHandler.Do(func() {
		mux := http.NewServeMux()
		mux.Handle("/", w.csrfMiddleware(http.HandlerFunc(w.listKeys)))
		mux.Handle("/users", w.csrfMiddleware(http.HandlerFunc(w.users)))
		mux.HandleFunc("/registration/begin", w.beginRegistration)
		mux.HandleFunc("/registration/finish", w.finishRegistration)
		w.handler = w.oidcMiddleware.Wrap(mux)
	})
	w.handler.ServeHTTP(rw, req)
}

// listKeys is the "index" page for a users credentials. It can be used to add,
func (w *webauthnManager) listKeys(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		http.Error(rw, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	responded, overriden, u := w.userForReq(rw, req)
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
		default:
			w.httpErr(req.Context(), rw, fmt.Errorf("unknown action %s", req.Form.Get("action")))
			return
		}
		// TODO - we need to track this some other way, in case form doesn't include it?
		http.Redirect(rw, req, w.pathFor(req.URL.Path)+"?"+req.URL.Query().Encode(), http.StatusSeeOther)
		return
	}

	// need to propogate this to the JS callbacks. TODO - This is janky,
	// consider putting it in the session or something
	waq := ""
	if overriden {
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
		http.Redirect(rw, req, w.pathFor(req.URL.Path), http.StatusSeeOther)
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
		Email:    form.Get("email"),
		FullName: form.Get("fullName"),
	}
	if u.Email == "" || u.FullName == "" {
		// TODO - more elegant than a 500
		return fmt.Errorf("email and full name must be specified")
	}
	if _, err := w.store.CreateUser(ctx, &u); err != nil {
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

func (w *webauthnManager) beginRegistration(rw http.ResponseWriter, req *http.Request) {
	responded, _, u := w.userForReq(rw, req)
	if responded {
		return
	}

	keyName := req.URL.Query().Get("key_name")
	if keyName == "" {
		w.httpErr(req.Context(), rw, fmt.Errorf("key name required"))
		return
	}

	options, sessionData, err := w.webauthn.BeginRegistration(u)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnmgrSessionName)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	sess.Values["keyname"] = keyName
	sess.Values["registration"] = *sessionData
	if err := ss.Save(req, rw, sess); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
}

func (w *webauthnManager) finishRegistration(rw http.ResponseWriter, req *http.Request) {
	responded, _, u := w.userForReq(rw, req)
	if responded {
		return
	}

	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnmgrSessionName)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}
	sessionData, ok := sess.Values["registration"].(webauthn.SessionData)
	if !ok {
		w.httpErr(req.Context(), rw, fmt.Errorf("session data not in session"))
		return
	}
	delete(sess.Values, "registration")
	keyName := sess.Values["keyname"].(string)
	delete(sess.Values, "keyname")
	if err := ss.Save(req, rw, sess); err != nil {
		w.httpErr(req.Context(), rw, err)
		return
	}

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
}

// userForReq gets the user for a given request, accounting for the override_uid
// / admin params. it will handle reponse to user, indicating if it does via the
// return. If it has, the caller should simply return
func (w *webauthnManager) userForReq(rw http.ResponseWriter, req *http.Request) (responded, overriden bool, u *WebauthnUser) {
	overriden = false

	claims := oidcm.ClaimsFromContext(req.Context())
	if claims == nil {
		w.httpUnauth(rw, "")
		return true, overriden, nil
	}

	uid := claims.Subject
	if req.URL.Query().Get("override_uid") != "" && w.isAdmin(claims.Subject) {
		// impersonation path = we allow user to override the user ID to perform
		// actions as the targeted user
		uid = req.URL.Query().Get("override_uid")
		overriden = true
	}

	u, ok, err := w.store.GetUserByID(req.Context(), uid)
	if err != nil {
		w.httpErr(req.Context(), rw, err)
		return true, overriden, nil
	}
	if !ok {
		w.httpNotFound(rw)
		return true, overriden, nil
	}

	return false, overriden, u
}

func (w *webauthnManager) pathFor(path string) string {
	return w.httpPrefix + path
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
		"pathFor": w.pathFor,
		csrf.TemplateTag: func() template.HTML {
			return csrf.TemplateField(r)
		},
		"b64": base64.URLEncoding.EncodeToString,
	}

	lt, err := template.New("").Funcs(funcs).ParseFS(webauthnTemplateData, "web/templates/webauthn/layout.tmpl.html")
	if err != nil {
		w.httpErr(r.Context(), rw, err)
	}
	t, err := lt.ParseFS(webauthnTemplateData, "web/templates/webauthn/"+templateName)
	if err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
	if err := t.ExecuteTemplate(rw, templateName, data); err != nil {
		w.httpErr(r.Context(), rw, err)
		return
	}
}
