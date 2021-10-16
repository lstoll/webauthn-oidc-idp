package main

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"sync"
	"text/template"

	oidcm "github.com/pardot/oidc/middleware"
	"go.uber.org/zap"
)

//go:embed web/templates/webauthn/*
var webauthnTemplateData embed.FS

type WebauthnUserStore interface {
	GetUserByID(ctx context.Context, id string) (*DynamoWebauthnUser, bool, error)
	GetUserByEmail(ctx context.Context, email string) (*DynamoWebauthnUser, bool, error)
	PutUser(ctx context.Context, u *DynamoWebauthnUser) (id string, err error)
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
	}
	uid := claims.Subject
	if req.URL.Query().Get("override_uid") != "" && w.isAdmin(claims.Subject) {
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

func (w *webauthnManager) execTemplate(rw http.ResponseWriter, data interface{}) {
	// TODO - init earlier, to catch errors?
	template.Must(
		template.New("").
			Funcs(template.FuncMap{
				"pathFor": w.pathFor,
			}).
			ParseFS(webauthnTemplateData, "web/templates/webauthn/*.tmpl.html"),
	).Execute(rw, data)
}
