package auth

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"uuid"

	"lds.li/passidp/internal/storage"
	"lds.li/web"
	"lds.li/web/httperror"
)

type credentialInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at,omitzero"`
}

type listCredentialsResponse struct {
	Credentials []credentialInfo `json:"credentials"`
}

func (a *Authenticator) HandleListCredentials(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	var creds []storage.UserCredential
	a.CredStore.Read(func(cs *storage.CredentialStore) {
		creds = cs.UserCredentials(*userID)
	})

	sort.Slice(creds, func(i, j int) bool {
		return creds[i].CreatedAt.After(creds[j].CreatedAt)
	})

	resp := listCredentialsResponse{Credentials: []credentialInfo{}}
	for _, cred := range creds {
		info := credentialInfo{
			ID:   cred.ID.String(),
			Name: cred.Name,
		}
		if !cred.CreatedAt.IsZero() {
			info.CreatedAt = cred.CreatedAt.Format(time.RFC3339)
		}
		resp.Credentials = append(resp.Credentials, info)
	}

	return w.WriteResponse(r, &web.JSONResponse{Data: resp})
}

func (a *Authenticator) HandleDeleteCredential(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	idStr, ok := strings.CutPrefix(r.URL().Path, "/api/credentials/")
	if !ok || idStr == "" {
		return httperror.BadRequestErrf("credential ID required")
	}
	credentialID, err := uuid.Parse(idStr)
	if err != nil {
		return httperror.BadRequestErrf("invalid credential ID")
	}

	var found bool
	if err := a.CredStore.Write(func(cs *storage.CredentialStore) error {
		found = cs.DeleteUserCredential(*userID, credentialID)
		return nil
	}); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if !found {
		return httperror.NotFoundErrf("credential not found")
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
