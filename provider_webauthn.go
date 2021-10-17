package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/pardot/oidc/core"
	"go.uber.org/zap"
)

const (
	webauthnSessionName = "wn"
)

var (
	_ embedProvider = (*OIDCProvider)(nil)
	_ http.Handler  = (*OIDCProvider)(nil)
)

type webauthnProvider struct {
	logger     *zap.SugaredLogger
	name       string
	store      WebauthnUserStore
	asm        AuthSessionManager
	webauthn   *webauthn.WebAuthn
	httpPrefix string

	handler     http.Handler
	initHandler sync.Once
}

func (w *webauthnProvider) LoginPanel(r *http.Request, ar *core.AuthorizationRequest) (template.HTML, error) {
	return template.HTML(`

	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
	<script>

	class WebAuthn {
		// Decode a base64 string into a Uint8Array.
		static _decodeBuffer(value) {
			return Uint8Array.from(atob(value), c => c.charCodeAt(0));
		}

		// Encode an ArrayBuffer into a urlbase64 string.
		static _encodeBuffer(value) {
			return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
				.replace(/\+/g, "-")
				.replace(/\//g, "_")
				.replace(/=/g, "");;
		}

		// Checks whether the status returned matches the status given.
		static _checkStatus(status) {
			return res => {
				if (res.status === status) {
					return res;
				}
				throw new Error(res.statusText);
			};
		}

		login() {
			let email = $("#email").val()
			if (email === "") {
			alert("Please enter a email");
			return;
			}

			return fetch('` + w.httpPrefix + `/start?email=' + email + '&sessionID=` + ar.SessionID + `', {
					method: 'POST',
					body: JSON.stringify({}) // TODO - better than query string
				})
				.then(WebAuthn._checkStatus(200))
				.then(res => res.json())
				.then(res => {
					res.publicKey.challenge = WebAuthn._decodeBuffer(res.publicKey.challenge);
					if (res.publicKey.allowCredentials) {
						for (let i = 0; i < res.publicKey.allowCredentials.length; i++) {
							res.publicKey.allowCredentials[i].id = WebAuthn._decodeBuffer(res.publicKey.allowCredentials[i].id);
						}
					}
					return res;
				})
				.then(res => navigator.credentials.get(res))
				.then(credential => {
					return fetch('` + w.httpPrefix + `/finish?email=' + email + '&sessionID=` + ar.SessionID + `', {
						method: 'POST',
						headers: {
							'Accept': 'application/json',
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							id: credential.id,
							rawId: WebAuthn._encodeBuffer(credential.rawId),
							type: credential.type,
							response: {
								clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON),
								authenticatorData: WebAuthn._encodeBuffer(credential.response.authenticatorData),
								signature: WebAuthn._encodeBuffer(credential.response.signature),
								userHandle: WebAuthn._encodeBuffer(credential.response.userHandle)
							}
						}),
					})
				})
				.then(WebAuthn._checkStatus(200));
		}
	}

	let w = new WebAuthn();

	let loginPending = false;

	function doLogin() {
		if (loginPending) return;
		loginPending = true;
		// document.getElementById("loginLoading").classList.remove("hide");
		w.login({ "username": document.getElementById("email").value })
			// .then(res => res.json())
			.then(res => {
				window.location.href = '` + w.httpPrefix + `/loggedin';
			})
			.catch(err => {
				console.error(err);
				alert('Failed to login: ' + err);
			})
			.then(() => {
				loginPending = false;
				// document.getElementById("loginLoading").classList.add("hide");
			});
	}

  </script>

  <div>
  <h3>webauthn</h3>
  <label for="email">Email:</label>
  <input id="email" name="email" type="text">
  <button onclick="doLogin()">Login</button>
  </div>

	`), nil
}

func (w *webauthnProvider) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	w.initHandler.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/start", w.startLogin)
		mux.HandleFunc("/finish", w.finishLogin)
		mux.HandleFunc("/loggedin", w.loggedIn)

		w.handler = mux
	})
	w.handler.ServeHTTP(rw, req)
}

func (w *webauthnProvider) startLogin(rw http.ResponseWriter, req *http.Request) {
	email := req.URL.Query().Get("email")

	log.Printf("start for %s", email)

	u, ok, err := w.store.GetUserByEmail(req.Context(), email)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	if !ok {
		// TODO - better response
		w.httpErr(rw, fmt.Errorf("no user for email"))
		return
	}

	options, sessionData, err := w.webauthn.BeginLogin(u)
	if err != nil {
		w.httpErr(rw, err)
		return
	}

	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	sess.Values["login"] = *sessionData
	if err := ss.Save(req, rw, sess); err != nil {
		w.httpErr(rw, err)
		return
	}

	if err := json.NewEncoder(rw).Encode(options); err != nil {
		w.httpErr(rw, err)
		return
	}
}

func (w *webauthnProvider) finishLogin(rw http.ResponseWriter, req *http.Request) {
	var (
		email     = req.URL.Query().Get("email")
		sessionID = req.URL.Query().Get("sessionID")
	)

	u, ok, err := w.store.GetUserByEmail(req.Context(), email)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	if !ok {
		// TODO - better response
		w.httpErr(rw, fmt.Errorf("no user for email"))
		return
	}

	// var car protocol.CredentialAssertionResponse

	// if err := json.NewDecoder(req.Body).Decode(&car); err != nil {
	// 	w.httpErr(rw, err)
	// 	return
	// }
	// log.Printf("car: %#v", car)

	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	sessionData, ok := sess.Values["login"].(webauthn.SessionData)
	if !ok {
		w.httpErr(rw, fmt.Errorf("session data not in session"))
		return
	}
	delete(sess.Values, "login")

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(req.Body)
	if err != nil {
		w.httpErr(rw, fmt.Errorf("parsing credential creation response: %v", err))
		return
	}
	credential, err := w.webauthn.ValidateLogin(u, sessionData, parsedResponse)
	if err != nil {
		w.httpErr(rw, fmt.Errorf("validating login: %v", err))
		return
	}

	// update the credential for the counter etc.
	u.UpdateWebauthnCredential(credential)
	if _, err := w.store.PutUser(req.Context(), u); err != nil {
		w.httpErr(rw, err)
		return
	}

	sess.Values["authd_user"] = webauthnLogin{
		UserID:      u.ID,
		SessionID:   sessionID,
		ValidBefore: time.Now().Add(15 * time.Second),
	}

	if err := ss.Save(req, rw, sess); err != nil {
		w.httpErr(rw, err)
		return
	}

	// OK (respond with URL here)
}

func (w *webauthnProvider) loggedIn(rw http.ResponseWriter, req *http.Request) {
	ss := sessionStoreFromContext(req.Context())
	sess, err := ss.Get(req, webauthnSessionName)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	login, ok := sess.Values["authd_user"].(webauthnLogin)
	if !ok {
		w.httpErr(rw, fmt.Errorf("can't find authd_user in session"))
		return
	}
	delete(sess.Values, "authd_user")
	if err := ss.Save(req, rw, sess); err != nil {
		w.httpErr(rw, err)
		return
	}

	if login.ValidBefore.Before(time.Now()) {
		w.httpErr(rw, fmt.Errorf("login expired"))
		return
	}

	u, ok, err := w.store.GetUserByID(req.Context(), login.UserID)
	if err != nil {
		w.httpErr(rw, err)
		return
	}
	if !ok {
		w.httpErr(rw, fmt.Errorf("no user found"))
		return
	}

	// This is a user-facing redirect item. We might need to update upstream to
	// help do it more inline with webauthn info. In the mean time we have the
	// webauthn page redirect here, with the user ID in the session. we can get
	// the user info out of this, and then finalize the session and let it
	// render Access issues, or a redirect to the final location.

	// finalize it. this will redirect the user to the appropriate place
	w.asm.Authenticate(rw, req, login.SessionID, Authentication{
		Subject:  u.ID,
		EMail:    u.Email,
		FullName: u.FullName,
		// TODO other fields
	})
}

func (w *webauthnProvider) httpErr(rw http.ResponseWriter, err error) {
	w.logger.Error(err)
	http.Error(rw, "Internal Error", http.StatusInternalServerError)
}

type webauthnLogin struct {
	UserID      string
	ValidBefore time.Time
	SessionID   string
}

var _ = func() struct{} {
	gob.Register(webauthnLogin{})
	return struct{}{}
}()
