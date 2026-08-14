package admin

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
)

// CredentialInfo describes a stored passkey credential.
type CredentialInfo struct {
	ID        string
	Name      string
	UserID    string
	UserName  string
	UserEmail string
	CreatedAt string
}

// ListCredentials returns all credentials with user details from config.
func ListCredentials(cfg *config.Config, credStore *storage.CredentialFile) ([]CredentialInfo, error) {
	var credentials []CredentialInfo
	credStore.Read(func(cs *storage.CredentialStore) {
		for _, cred := range cs.Credentials {
			user, err := cfg.Users.GetUser(cred.UserID)
			userName := ""
			userEmail := ""
			if err == nil {
				userName = user.FullName
				userEmail = user.Email
			}

			credentials = append(credentials, CredentialInfo{
				ID:        cred.ID.String(),
				Name:      cred.Name,
				UserID:    cred.UserID.String(),
				UserName:  userName,
				UserEmail: userEmail,
				CreatedAt: cred.CreatedAt.Format(time.RFC3339),
			})
		}
	})
	return credentials, nil
}

// DeleteCredential removes a credential by ID.
func DeleteCredential(credStore *storage.CredentialFile, credentialID uuid.UUID) error {
	var found bool
	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		for i, cred := range cs.Credentials {
			if cred.ID == credentialID {
				cs.Credentials[i] = cs.Credentials[len(cs.Credentials)-1]
				cs.Credentials = cs.Credentials[:len(cs.Credentials)-1]
				found = true
				return nil
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}

	if !found {
		return fmt.Errorf("credential not found")
	}
	return nil
}
