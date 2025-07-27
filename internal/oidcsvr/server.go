package oidcsvr

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as"
	"github.com/lstoll/web"
	"github.com/lstoll/web/httperror"
	"github.com/lstoll/webauthn-oidc-idp/internal/auth"
)

func init() {
	gob.Register(&sessionAuthRequests{})
	gob.Register(&oauth2as.AuthRequest{})
}

const (
	sessionKeyAuthRequest = "authRequest"
)

type sessionAuthRequests struct {
	Requests map[string]oauth2as.AuthRequest
}

type Server struct {
	Auth     *auth.Authenticator
	OAuth2AS *oauth2as.Server
}

func (s *Server) AddHandlers(r *web.Server) {
	r.Handle("GET /authorization", web.BrowserHandlerFunc(s.HandleAuthorizationRequest), auth.SkipAuthn)
	r.Handle("GET /resumeAuthorization", web.BrowserHandlerFunc(s.HandleAuthorizationRequestReturn), auth.SkipAuthn)

	r.Handle("POST /token", s.OAuth2AS, auth.SkipAuthn)
	r.Handle("GET /userinfo", s.OAuth2AS, auth.SkipAuthn)
	r.Handle("GET /.well-known/openid-configuration", s.OAuth2AS, auth.SkipAuthn)
	r.Handle("GET /.well-known/jwks.json", s.OAuth2AS, auth.SkipAuthn)
}

func (s *Server) HandleAuthorizationRequest(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	authReq, err := s.OAuth2AS.ParseAuthRequest(r.RawRequest())
	if err != nil {
		return err
	}

	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		// stash req in session, set return to with ID.
		sessAuthReqs, ok := r.Session().Get(sessionKeyAuthRequest).(*sessionAuthRequests)
		if !ok {
			sessAuthReqs = &sessionAuthRequests{
				Requests: make(map[string]oauth2as.AuthRequest),
			}
		}

		reqID := uuid.New().String()
		sessAuthReqs.Requests[reqID] = *authReq
		r.Session().Set(sessionKeyAuthRequest, sessAuthReqs)

		s.Auth.TriggerLogin(w, r.RawRequest(), "/resumeAuthorization?id="+reqID)
		return nil
	}

	redir, err := s.createGrant(ctx, authReq, *userID)
	if err != nil {
		return err
	}

	return w.WriteResponse(r, &web.RedirectResponse{
		URL:  redir,
		Code: http.StatusSeeOther,
	})
}

func (s *Server) HandleAuthorizationRequestReturn(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}
	reqID := r.URL().Query().Get("id")
	if reqID == "" {
		return httperror.BadRequestErrf("no request ID")
	}
	sessAuthReqs, ok := r.Session().Get(sessionKeyAuthRequest).(*sessionAuthRequests)
	if !ok {
		return httperror.BadRequestErrf("no requests in session")
	}

	authReq, ok := sessAuthReqs.Requests[reqID]
	if !ok {
		return httperror.BadRequestErrf("no request in session")
	}

	redir, err := s.createGrant(ctx, &authReq, *userID)
	if err != nil {
		return err
	}

	return w.WriteResponse(r, &web.RedirectResponse{
		URL:  redir,
		Code: http.StatusSeeOther,
	})
}

func (s Server) createGrant(ctx context.Context, request *oauth2as.AuthRequest, userID uuid.UUID) (returnTo string, _ error) {
	grant := &oauth2as.AuthGrant{
		Request: request,
		UserID:  userID.String(),
		// TODO - set scopes appropriately
		GrantedScopes: request.Scopes,
	}
	redir, err := s.OAuth2AS.GrantAuth(ctx, grant)
	if err != nil {
		return "", fmt.Errorf("grant auth: %w", err)
	}
	return redir, nil
}
