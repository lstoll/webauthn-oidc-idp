package admin

import (
	"fmt"
	"time"
	"uuid"

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
			credentials = append(credentials, credentialInfo(cfg, cred.ID, cred.Name, cred.UserID, cred.CreatedAt))
		}
		for _, user := range cs.Users {
			for _, passkey := range user.Passkeys {
				credentials = append(credentials, credentialInfo(cfg, passkey.ID, passkey.Name, user.AccountID, passkey.CreatedAt))
			}
		}
	})
	return credentials, nil
}

func credentialInfo(cfg *config.Config, id uuid.UUID, name string, userID uuid.UUID, createdAt time.Time) CredentialInfo {
	userName := ""
	userEmail := ""
	if user, err := cfg.Users.GetUser(userID); err == nil {
		userName = user.FullName
		userEmail = user.Email
	}
	created := ""
	if !createdAt.IsZero() {
		created = createdAt.Format(time.RFC3339)
	}
	return CredentialInfo{
		ID:        id.String(),
		Name:      name,
		UserID:    userID.String(),
		UserName:  userName,
		UserEmail: userEmail,
		CreatedAt: created,
	}
}

// DeleteCredential removes a credential by ID.
func DeleteCredential(credStore *storage.CredentialFile, credentialID uuid.UUID) error {
	var found bool
	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		for i, cred := range cs.Credentials {
			if cred.ID == credentialID {
				cs.Credentials = append(cs.Credentials[:i], cs.Credentials[i+1:]...)
				found = true
				return nil
			}
		}
		for _, user := range cs.Users {
			for i, passkey := range user.Passkeys {
				if passkey.ID == credentialID {
					user.Passkeys = append(user.Passkeys[:i], user.Passkeys[i+1:]...)
					found = true
					return nil
				}
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
