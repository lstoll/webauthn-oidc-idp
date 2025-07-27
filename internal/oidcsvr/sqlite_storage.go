package oidcsvr

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
)

var _ oauth2as.Storage = (*SQLiteStorage)(nil)

// SQLiteStorage implements oauth2as.Storage using SQLite
type SQLiteStorage struct {
	queries *queries.Queries
}

// NewSQLiteStorage creates a new SQLite storage implementation
func NewSQLiteStorage(db *sql.DB) *SQLiteStorage {
	return &SQLiteStorage{
		queries: queries.New(db),
	}
}

// CreateGrant creates a new grant
func (s *SQLiteStorage) CreateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error {
	requestData, err := json.Marshal(grant.Request)
	if err != nil {
		return fmt.Errorf("marshal request data: %w", err)
	}

	grantedScopes, err := json.Marshal(grant.GrantedScopes)
	if err != nil {
		return fmt.Errorf("marshal granted scopes: %w", err)
	}

	var authCode, refreshToken sql.NullString
	if grant.AuthCode != nil && *grant.AuthCode != "" {
		authCode.String = *grant.AuthCode
		authCode.Valid = true
	}
	if grant.RefreshToken != nil && *grant.RefreshToken != "" {
		refreshToken.String = *grant.RefreshToken
		refreshToken.Valid = true
	}

	params := queries.CreateGrantParams{
		ID:            grant.ID,
		AuthCode:      authCode,
		RefreshToken:  refreshToken,
		UserID:        grant.UserID,
		ClientID:      grant.ClientID,
		GrantedScopes: string(grantedScopes),
		RequestData:   requestData,
		ExpiresAt:     grant.ExpiresAt,
	}

	return s.queries.CreateGrant(ctx, params)
}

// UpdateGrant updates an existing grant
func (s *SQLiteStorage) UpdateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error {
	requestData, err := json.Marshal(grant.Request)
	if err != nil {
		return fmt.Errorf("marshal request data: %w", err)
	}

	grantedScopes, err := json.Marshal(grant.GrantedScopes)
	if err != nil {
		return fmt.Errorf("marshal granted scopes: %w", err)
	}

	var authCode, refreshToken sql.NullString
	if grant.AuthCode != nil && *grant.AuthCode != "" {
		authCode.String = *grant.AuthCode
		authCode.Valid = true
	}
	if grant.RefreshToken != nil && *grant.RefreshToken != "" {
		refreshToken.String = *grant.RefreshToken
		refreshToken.Valid = true
	}

	params := queries.UpdateGrantParams{
		AuthCode:      authCode,
		RefreshToken:  refreshToken,
		UserID:        grant.UserID,
		ClientID:      grant.ClientID,
		GrantedScopes: string(grantedScopes),
		RequestData:   requestData,
		ExpiresAt:     grant.ExpiresAt,
		ID:            grant.ID,
	}

	return s.queries.UpdateGrant(ctx, params)
}

// ExpireGrant expires a grant by setting its expiry to now
func (s *SQLiteStorage) ExpireGrant(ctx context.Context, id uuid.UUID) error {
	return s.queries.ExpireGrant(ctx, id)
}

// GetGrant retrieves a grant by ID
func (s *SQLiteStorage) GetGrant(ctx context.Context, id uuid.UUID) (*oauth2as.StoredGrant, error) {
	grant, err := s.queries.GetGrant(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get grant: %w", err)
	}

	return s.convertGrant(grant)
}

// GetGrantByAuthCode retrieves a grant by authorization code
func (s *SQLiteStorage) GetGrantByAuthCode(ctx context.Context, authCode string) (*oauth2as.StoredGrant, error) {
	nullAuthCode := sql.NullString{String: authCode, Valid: true}
	grant, err := s.queries.GetGrantByAuthCode(ctx, nullAuthCode)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get grant by auth code: %w", err)
	}

	return s.convertGrant(grant)
}

// GetGrantByRefreshToken retrieves a grant by refresh token
func (s *SQLiteStorage) GetGrantByRefreshToken(ctx context.Context, refreshToken string) (*oauth2as.StoredGrant, error) {
	nullRefreshToken := sql.NullString{String: refreshToken, Valid: true}
	grant, err := s.queries.GetGrantByRefreshToken(ctx, nullRefreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get grant by refresh token: %w", err)
	}

	return s.convertGrant(grant)
}

// convertGrant converts a database Grant to oauth2as.StoredGrant
func (s *SQLiteStorage) convertGrant(grant queries.Grant) (*oauth2as.StoredGrant, error) {
	var request oauth2as.AuthRequest
	if err := json.Unmarshal(grant.RequestData, &request); err != nil {
		return nil, fmt.Errorf("unmarshal request data: %w", err)
	}

	var grantedScopes []string
	if err := json.Unmarshal([]byte(grant.GrantedScopes), &grantedScopes); err != nil {
		return nil, fmt.Errorf("unmarshal granted scopes: %w", err)
	}

	storedGrant := &oauth2as.StoredGrant{
		ID:            grant.ID,
		UserID:        grant.UserID,
		ClientID:      grant.ClientID,
		GrantedScopes: grantedScopes,
		Request:       &request,
		GrantedAt:     grant.CreatedAt,
		ExpiresAt:     grant.ExpiresAt,
	}

	if grant.AuthCode.Valid {
		storedGrant.AuthCode = &grant.AuthCode.String
	}
	if grant.RefreshToken.Valid {
		storedGrant.RefreshToken = &grant.RefreshToken.String
	}

	return storedGrant, nil
}

// CleanupExpiredGrants removes expired grants from the database
func (s *SQLiteStorage) CleanupExpiredGrants(ctx context.Context) error {
	return s.queries.CleanupExpiredGrants(ctx)
}
