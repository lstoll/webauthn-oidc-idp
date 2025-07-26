package auth

import (
	"context"

	"github.com/lstoll/web"
	"github.com/lstoll/webauthn-oidc-idp/internal/webcommon"
)

type Authenticator struct{}

// HandleIndex is a temporary handler, just to get a webauthn UI up and running.
func (a *Authenticator) HandleIndex(ctx context.Context, w web.ResponseWriter, r *web.Request) error {

	// Example: User not logged in
	return w.WriteResponse(r, &web.TemplateResponse{
		Name: "login.html.tmpl",
		Data: webcommon.TemplateData{
			Title:        "Login - IDP",
			UserLoggedIn: false,
			Username:     "",
		},
		Templates: webcommon.Templates,
	})
}
