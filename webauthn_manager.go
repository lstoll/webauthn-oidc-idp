package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/csrf"
	oidcm "github.com/pardot/oidc/middleware"
	"go.uber.org/zap"
)

//go:embed web/templates/webauthn/*
var webauthnTemplateData embed.FS

type WebauthnUserStore interface {
	GetUserByID(ctx context.Context, id string) (*DynamoWebauthnUser, bool, error)
	GetUserByEmail(ctx context.Context, email string) (*DynamoWebauthnUser, bool, error)
	PutUser(ctx context.Context, u *DynamoWebauthnUser) (id string, err error)
	ListUsers(ctx context.Context) ([]*DynamoWebauthnUser, error)
	DeleteUser(ctx context.Context, id string) error
}

type webauthnManager struct {
	logger *zap.SugaredLogger
	store  WebauthnUserStore

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
	w.logger.Debug("serve http called")
	w.initHandler.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", w.listKeys)
		mux.Handle("/users", w.csrfMiddleware(http.HandlerFunc(w.users)))

		w.handler = w.oidcMiddleware.Wrap(mux)
	})
	w.handler.ServeHTTP(rw, req)
}

// listKeys is the "index" page for a users credentials. It can be used to add,
func (w *webauthnManager) listKeys(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(rw, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	claims := oidcm.ClaimsFromContext(req.Context())
	if claims == nil {
		w.httpUnauth(rw, "")
		return
	}
	uid := claims.Subject
	if req.URL.Query().Get("override_uid") != "" && w.isAdmin(claims.Subject) {
		// impersonation path = we allow user to override the user ID to perform
		// actions as the targeted user
		uid = req.URL.Query().Get("override_uid")
	}
	u, ok, err := w.store.GetUserByID(req.Context(), uid)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	if !ok {
		w.httpNotFound(rw)
		return
	}
	_ = u

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
				w.httpErr(rw, err)
				return
			}
		case "delete":
			if err := w.deleteUser(req.Context(), req.Form); err != nil {
				w.httpErr(rw, err)
				return
			}
		default:
			w.httpErr(rw, fmt.Errorf("unknown action %s", req.Form.Get("action")))
			return
		}
		http.Redirect(rw, req, w.pathFor(req.URL.Path), http.StatusSeeOther)
		return
	}

	users, err := w.store.ListUsers(req.Context())
	if err != nil {
		w.httpErr(rw, err)
		return
	}

	w.execTemplate(rw, req, "admin_users.tmpl.html", map[string]interface{}{"Users": users})
}

// addUser handles POSTS to the user page, to create a user
func (w *webauthnManager) addUser(ctx context.Context, form url.Values) error {
	u := DynamoWebauthnUser{
		Email:    form.Get("email"),
		FullName: form.Get("fullName"),
	}
	if u.Email == "" || u.FullName == "" {
		// TODO - more elegant than a 500
		return fmt.Errorf("email and full name must be specified")
	}
	if _, err := w.store.PutUser(ctx, &u); err != nil {
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

func (w *webauthnManager) pathFor(path string) string {
	return w.httpPrefix + path
}

func (w *webauthnManager) httpErr(rw http.ResponseWriter, err error) {
	w.logger.Error(err)
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
	}

	lt, err := template.New("").Funcs(funcs).ParseFS(webauthnTemplateData, "web/templates/webauthn/layout.tmpl.html")
	if err != nil {
		w.httpErr(rw, err)
	}
	t, err := lt.ParseFS(webauthnTemplateData, "web/templates/webauthn/"+templateName)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	if err := t.ExecuteTemplate(rw, templateName, data); err != nil {
		w.httpErr(rw, err)
		return
	}
}
