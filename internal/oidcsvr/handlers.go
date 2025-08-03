package oidcsvr

import (
	"context"
	"crypto/md5"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as"
	"github.com/lstoll/oauth2ext/claims"
	"github.com/lstoll/webauthn-oidc-idp/internal/clients"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

type Handlers struct {
	Issuer  string
	Queries *queries.Queries
	Clients *clients.StaticClients
}

func (h *Handlers) TokenHandler(ctx context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
	slog.Info("token handler", "clientID", req.ClientID, "scopes", req.GrantedScopes)

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Queries.GetUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	cl, ok := h.Clients.GetClient(req.ClientID)
	if !ok {
		return nil, fmt.Errorf("client %s not found", req.ClientID)
	}

	resp := &oauth2as.TokenResponse{
		IDClaims: &claims.RawIDClaims{
			Extra: map[string]any{
				"email":          user.Email,
				"email_verified": true,
				"picture":        gravatarURL(user.Email),
				"name":           user.FullName,
			},
		},
	}

	if cl.UseOverrideSubject && user.OverrideSubject.Valid {
		resp.OverrideIDSubject = user.OverrideSubject.String
	}

	return resp, nil
}

func (h *Handlers) UserinfoHandler(ctx context.Context, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
	// TODO - the req should have the grant/scopes, so we can determine what to
	// give access to.

	userUUID, err := uuid.Parse(uireq.Subject)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Queries.GetUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	cl := claims.RawIDClaims{
		Issuer:  h.Issuer,
		Subject: uireq.Subject,
		Extra:   make(map[string]any),
	}
	cl.Extra["email"] = user.Email
	cl.Extra["email_verified"] = true
	cl.Extra["picture"] = gravatarURL(user.Email) // thank u tom
	cl.Extra["name"] = user.FullName
	nsp := strings.Split(user.FullName, " ")
	if len(nsp) == 2 {
		cl.Extra["given_name"] = nsp[0]
		cl.Extra["family_name"] = nsp[1]
	}
	return &oauth2as.UserinfoResponse{
		Identity: &cl,
	}, nil
}

func gravatarURL(email string) string {
	hash := md5.Sum([]byte(email))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x.png", hash)
}
