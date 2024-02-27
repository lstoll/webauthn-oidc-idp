package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Authentication are the details flagged for an authenticated user of the
// system.
type Authentication struct {
	// Subject (required) is the unique identifier for the authenticated user.
	// This should be stable over time.
	Subject string `json:"subject"`
	// EMail (optional), for when the email/profile scope is requested
	EMail string `json:"email,omitempty"`
	// FullName (optional), for when the profile scope is requested
	FullName string `json:"full_name,omitempty"`
	// Groups (optional), for when the groups scope is requested
	Groups []string `json:"groups,omitempty"`
	// ExtraClaims (optional) fields to add to the returned ID token claims
	ExtraClaims map[string]interface{} `json:"extra_claims,omitempty"`
	// PolicyContext is internal data, that is passed to the policies that are
	// evaluated downstream. This data is not presented to the user.
	PolicyContext map[string]interface{} `json:"policy_context,omitempty"`
}

func (s *storage) Authenticate(ctx context.Context, sessionID string, auth Authentication) error {
	b, err := json.Marshal(auth)
	if err != nil {
		return fmt.Errorf("marshaling authentication %s: %w", sessionID, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`update sessions set authentication=$1 where id=$2`,
		b, sessionID); err != nil {
		return fmt.Errorf("updating authentication %s: %w", sessionID, err)
	}
	return nil
}

func (s *storage) GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error) {
	var sessdata []byte
	if err := s.db.QueryRowContext(ctx, `
	select authentication from sessions where id = $1`,
		sessionID).Scan(&sessdata); err != nil {
		if err == sql.ErrNoRows {
			return Authentication{}, false, nil
		}
		return Authentication{}, false, fmt.Errorf("error getting authentication %s: %w", sessionID, err)
	}

	if sessdata == nil && len(sessdata) == 0 {
		return Authentication{}, false, nil
	}

	var a Authentication
	if err := json.Unmarshal(sessdata, &a); err != nil {
		return Authentication{}, false, fmt.Errorf("unmarshaling authentication %s: %w", sessionID, err)
	}

	return a, true, nil
}
