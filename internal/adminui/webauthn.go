package adminui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"lds.li/passidp/internal/admin"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
)

type registerData struct {
	webcommon.LayoutData
}

type WebAuthnManager struct {
	config      *config.Config
	credStore   *storage.CredentialFile
	enrollments *storage.EnrollmentStore
	webauthn    *webauthn.WebAuthn
}

func NewWebAuthnManager(config *config.Config, credStore *storage.CredentialFile, enrollments *storage.EnrollmentStore, webauthn *webauthn.WebAuthn) *WebAuthnManager {
	return &WebAuthnManager{
		config:      config,
		credStore:   credStore,
		enrollments: enrollments,
		webauthn:    webauthn,
	}
}

func (w *WebAuthnManager) AddHandlers(websvr *web.Server) {
	websvr.Handle("POST /registration/begin", web.BrowserHandlerFunc(w.beginRegistration))
	websvr.Handle("POST /registration/finish", web.BrowserHandlerFunc(w.finishRegistration))
	websvr.Handle("GET /registration", web.BrowserHandlerFunc(w.registration))
}

// registration is a page used to add a new key. It should handle either a user
// in the session (from the logged in keys page), or a boostrap token and user
// id as query params for an inactive user.
func (w *WebAuthnManager) registration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	// first, check the URL for a registration token and user id. If it exists,
	// check if we have a pending enrollment with matching token.
	uid := req.URL().Query().Get("user_id")
	et := req.URL().Query().Get("enrollment_token")
	if uid != "" && et != "" {
		// we want to enroll a user. Check for pending enrollment in state DB
		userID, err := uuid.Parse(uid)
		if err != nil {
			return fmt.Errorf("invalid user_id: %w", err)
		}

		enrollment, err := w.enrollments.GetPendingEnrollmentByKey(et)
		if err != nil {
			return fmt.Errorf("invalid enrollment token: %w", err)
		}

		if enrollment.UserID != userID {
			return fmt.Errorf("enrollment user_id mismatch")
		}

		sess := appsession.FromContext(ctx)
		data := sess.Get()
		data.Enrollment = &appsession.Enrollment{
			ForUserID:    uid,
			EnrollmentID: enrollment.ID.String(),
		}
		sess.Set(data)
	}

	// Get the pending enrollment from session
	pwe := appsession.FromContext(ctx).Get().Enrollment
	if pwe == nil || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	if pwe.EnrollmentID != "" {
		enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
		if err != nil {
			return fmt.Errorf("invalid enrollment_id: %w", err)
		}
		if _, err := w.enrollments.GetPendingEnrollmentByID(enrollmentID); err != nil {
			return fmt.Errorf("invalid enrollment: %w", err)
		}
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", pwe.ForUserID, err)
	}

	return rw.WriteResponse(req, &web.TemplateResponse{
		Templates: templates,
		Name:      "register.tmpl.html",
		Data: registerData{
			LayoutData: webcommon.LayoutData{
				Title:        "Register Passkey - IDP",
				UserLoggedIn: true,
				Username:     user.Email,
				UserFullName: user.FullName,
				UserEmail:    user.Email,
			},
		},
	})
}

func (w *WebAuthnManager) beginRegistration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	sess := appsession.FromContext(ctx)
	data := sess.Get()
	pwe := data.Enrollment
	if pwe == nil || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	if pwe.EnrollmentID != "" {
		enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
		if err != nil {
			return fmt.Errorf("invalid enrollment_id: %w", err)
		}
		if _, err := w.enrollments.GetPendingEnrollmentByID(enrollmentID); err != nil {
			return fmt.Errorf("invalid enrollment: %w", err)
		}
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", pwe.ForUserID, err)
	}

	// Get key name from query parameter
	keyName := req.URL().Query().Get("key_name")
	if keyName == "" {
		return fmt.Errorf("key name required")
	}

	authSelect := protocol.AuthenticatorSelection{
		RequireResidentKey: protocol.ResidentKeyRequired(),
		UserVerification:   protocol.VerificationRequired,
	}
	conveyancePref := protocol.ConveyancePreference(protocol.PreferDirectAttestation)

	var (
		passkeyUserID string
		existing      []webauthn.Credential
	)
	w.credStore.Read(func(cs *storage.CredentialStore) {
		passkeyUserID, _ = cs.PasskeyUserID(user.ID)
		existing = cs.WebAuthnCredentials(user.ID)
	})
	if passkeyUserID == "" {
		return fmt.Errorf("passkey user id missing for %s", user.ID)
	}

	options, sessionData, err := w.webauthn.BeginRegistration(auth.NewWebAuthnUser(user, passkeyUserID, existing), webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))
	if err != nil {
		return fmt.Errorf("beginning registration: %w", err)
	}

	pwe.KeyName = keyName
	pwe.WebAuthnData = sessionData
	data.Enrollment = pwe
	sess.Set(data)

	return rw.WriteResponse(req, &web.JSONResponse{
		Data: options,
	})
}

func (w *WebAuthnManager) finishRegistration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	sess := appsession.FromContext(ctx)
	data := sess.Get()
	pwe := data.Enrollment
	if pwe == nil || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("getting user %s: %w", pwe.ForUserID, err)
	}

	if pwe.WebAuthnData == nil {
		return fmt.Errorf("session data not in session")
	}
	sessionData := *pwe.WebAuthnData
	keyName := pwe.KeyName

	// purge the data from the session
	returnTo := pwe.ReturnTo
	data.Enrollment = nil
	sess.Set(data)

	// Parse the credential creation request from the body
	var credentialRequest json.RawMessage
	if err := req.UnmarshalJSONBody(&credentialRequest); err != nil {
		return fmt.Errorf("unmarshalling credential request: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credentialRequest))
	if err != nil {
		return fmt.Errorf("parsing credential creation response: %w", err)
	}

	var (
		passkeyUserID string
		existing      []webauthn.Credential
	)
	w.credStore.Read(func(cs *storage.CredentialStore) {
		passkeyUserID, _ = cs.PasskeyUserID(user.ID)
		existing = cs.WebAuthnCredentials(user.ID)
	})
	if passkeyUserID == "" {
		return fmt.Errorf("passkey user id missing for %s", user.ID)
	}

	credential, err := w.webauthn.CreateCredential(auth.NewWebAuthnUser(user, passkeyUserID, existing), sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("creating credential: %w", err)
	}

	if pwe.EnrollmentID == "" {
		return fmt.Errorf("no enrollment ID in session")
	}

	enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
	if err != nil {
		return fmt.Errorf("invalid enrollment_id: %w", err)
	}

	userID, err := uuid.Parse(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("invalid user_id: %w", err)
	}

	if err := admin.CompleteEnrollment(w.config, w.enrollments, w.credStore, userID, enrollmentID, credential, keyName); err != nil {
		return err
	}

	return rw.WriteResponse(req, &web.JSONResponse{
		Data: map[string]any{
			"success":  true,
			"message":  "Passkey registered successfully!",
			"returnTo": returnTo,
		},
	})
}
