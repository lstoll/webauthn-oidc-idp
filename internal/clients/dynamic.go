package clients

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/web"
	"lds.li/webauthn-oidc-idp/internal/auth"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

type DynamicClients struct {
	DB *queries.Queries
}

func (d *DynamicClients) AddHandlers(r *web.Server) {
	r.Handle("POST /registerClient", http.HandlerFunc(d.registerClient), auth.SkipAuthn)
}

// GetClient implements the ClientSource interface
func (d *DynamicClients) GetClient(clientID string) (*Client, bool) {
	// Only handle dynamic client IDs (prefixed with "dc.")
	if !strings.HasPrefix(clientID, "dc.") {
		return nil, false
	}

	ctx := context.Background()
	dbClient, err := d.DB.GetDynamicClient(ctx, clientID)
	if err != nil {
		return nil, false
	}

	// Parse the registration blob to get client details
	var registration oidcclientreg.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(dbClient.RegistrationBlob), &registration); err != nil {
		return nil, false
	}

	// Convert to Client struct - only include fields that are actually used by the OIDC flow
	client := &Client{
		ID:           dbClient.ID,
		RedirectURLs: registration.RedirectURIs,
		// For dynamic clients, we'll use the client secret from the registration response
		// The actual secret validation happens in ValidateClientSecret
		Secrets: []string{}, // Will be validated via hash comparison
		Public:  false,      // Dynamic clients are not public by default
	}

	return client, true
}

// GetClientMetadata returns the parsed client registration metadata for a given client ID
func (d *DynamicClients) GetClientMetadata(ctx context.Context, clientID string) (*oidcclientreg.ClientRegistrationRequest, error) {
	if !strings.HasPrefix(clientID, "dc.") {
		return nil, fmt.Errorf("client %s is not a dynamic client", clientID)
	}

	client, err := d.DB.GetDynamicClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client %s not found: %w", clientID, err)
	}

	var registration oidcclientreg.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(client.RegistrationBlob), &registration); err != nil {
		return nil, fmt.Errorf("failed to parse client registration for %s: %w", clientID, err)
	}

	return &registration, nil
}

// IsValidClientID implements oauth2as.ClientSource
func (d *DynamicClients) IsValidClientID(ctx context.Context, clientID string) (bool, error) {
	if !strings.HasPrefix(clientID, "dc.") {
		return false, nil
	}

	_, err := d.DB.GetDynamicClient(ctx, clientID)
	return err == nil, nil
}

// ClientOpts implements oauth2as.ClientSource
func (d *DynamicClients) ClientOpts(ctx context.Context, clientID string) ([]oauth2as.ClientOpt, error) {
	if !strings.HasPrefix(clientID, "dc.") {
		return nil, nil
	}

	client, err := d.DB.GetDynamicClient(ctx, clientID)
	if err != nil {
		return nil, nil
	}

	var opts []oauth2as.ClientOpt

	// Parse the registration blob to get client details
	var registration oidcclientreg.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(client.RegistrationBlob), &registration); err != nil {
		return nil, fmt.Errorf("failed to parse client registration: %w", err)
	}

	// Check if PKCE should be enforced based on application type and redirect URIs
	shouldEnforcePKCE := d.shouldEnforcePKCE(registration.ApplicationType, strings.Join(registration.RedirectURIs, ","))
	if !shouldEnforcePKCE {
		opts = append(opts, oauth2as.ClientOptSkipPKCE())
	}

	// Set signing algorithm based on client preference or default to RS256
	var signingAlg jwt.SigningAlg
	if registration.IDTokenSignedResponseAlg != "" {
		switch registration.IDTokenSignedResponseAlg {
		case "RS256":
			signingAlg = jwt.SigningAlgRS256
		case "ES256":
			signingAlg = jwt.SigningAlgES256
		default:
			// If the client requests an unsupported algorithm, default to RS256
			// This follows OIDC spec where the server can override client preferences
			signingAlg = jwt.SigningAlgRS256
		}
	} else {
		// Default to RS256 if no algorithm specified
		signingAlg = jwt.SigningAlgRS256
	}

	opts = append(opts, oauth2as.ClientOptSigningAlg(signingAlg))

	return opts, nil
}

// shouldEnforcePKCE determines if PKCE should be enforced for a client
func (d *DynamicClients) shouldEnforcePKCE(applicationType, redirectURIs string) bool {
	// Always enforce PKCE for native clients
	if applicationType == "native" {
		return true
	}

	// Always enforce PKCE for SPAs (Single Page Applications)
	if applicationType == "spa" {
		return true
	}

	// Check redirect URIs for localhost/127.0.0.1
	if redirectURIs != "" {
		uris := strings.Split(redirectURIs, ",")
		for _, uri := range uris {
			uri = strings.TrimSpace(uri)
			if uri == "" {
				continue
			}

			parsed, err := url.Parse(uri)
			if err != nil {
				continue
			}

			// Force PKCE for localhost and 127.0.0.1
			if parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
				return true
			}

			// Force PKCE for loopback addresses
			if strings.HasPrefix(parsed.Hostname(), "127.") {
				return true
			}
		}
	}

	return false
}

// ValidateClientSecret implements oauth2as.ClientSource
func (d *DynamicClients) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) (bool, error) {
	if !strings.HasPrefix(clientID, "dc.") {
		return false, fmt.Errorf("client %s not found", clientID)
	}

	client, err := d.DB.GetDynamicClient(ctx, clientID)
	if err != nil {
		return false, fmt.Errorf("client %s not found", clientID)
	}

	// Hash the provided secret
	hash := sha256.Sum256([]byte(clientSecret))
	providedHash := fmt.Sprintf("%x", hash)

	// Compare hashes using constant time comparison
	return subtle.ConstantTimeCompare([]byte(providedHash), []byte(client.ClientSecretHash)) == 1, nil
}

// RedirectURIs implements oauth2as.ClientSource
func (d *DynamicClients) RedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	if !strings.HasPrefix(clientID, "dc.") {
		return nil, fmt.Errorf("client %s not found", clientID)
	}

	client, err := d.DB.GetDynamicClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("client %s not found", clientID)
	}

	// Parse the registration blob to get redirect URIs
	var registration oidcclientreg.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(client.RegistrationBlob), &registration); err != nil {
		return nil, fmt.Errorf("failed to parse client registration: %w", err)
	}

	return registration.RedirectURIs, nil
}

func (d *DynamicClients) registerClient(w http.ResponseWriter, r *http.Request) {
	var req oidcclientreg.ClientRegistrationRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if err := d.validateClientRegistration(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate client ID and secret
	clientID := fmt.Sprintf("dc.%s", uuid.New().String())
	clientSecret := rand.Text()

	// Hash the secret for storage
	hash := sha256.Sum256([]byte(clientSecret))
	clientSecretHash := fmt.Sprintf("%x", hash)

	// Set expiration (14 days from now)
	expiresAt := time.Now().AddDate(0, 0, 14)

	// Store the entire request as metadata JSON
	metadataJSON, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "failed to marshal metadata", http.StatusInternalServerError)
		return
	}

	// Store in database
	params := queries.CreateDynamicClientParams{
		ID:               clientID,
		ClientSecretHash: clientSecretHash,
		RegistrationBlob: string(metadataJSON),
		ExpiresAt:        expiresAt,
	}

	if err := d.DB.CreateDynamicClient(r.Context(), params); err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}

	// Return the client registration response
	response := oidcclientreg.ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   ptr(expiresAt.Unix()),
		RegistrationAccessToken: "", // Not implemented for now
		RegistrationClientURI:   "", // Not implemented for now
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (d *DynamicClients) validateClientRegistration(req *oidcclientreg.ClientRegistrationRequest) error {
	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is required")
	}

	// Validate each redirect URI
	for i, uri := range req.RedirectURIs {
		if uri == "" {
			return fmt.Errorf("redirect_uri[%d] cannot be empty", i)
		}

		parsed, err := url.Parse(uri)
		if err != nil {
			return fmt.Errorf("redirect_uri[%d] is not a valid URL: %w", i, err)
		}

		// Must have a scheme
		if parsed.Scheme == "" {
			return fmt.Errorf("redirect_uri[%d] must have a scheme (http:// or https://)", i)
		}

		// Only allow http and https schemes
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("redirect_uri[%d] must use http:// or https:// scheme", i)
		}

		// Must have a host
		if parsed.Host == "" {
			return fmt.Errorf("redirect_uri[%d] must have a host", i)
		}

		// For localhost, allow any port
		if parsed.Hostname() == "localhost" {
			continue
		}

		// For 127.x.x.x addresses, allow any port
		if strings.HasPrefix(parsed.Hostname(), "127.") {
			continue
		}

		// For other hosts, require HTTPS (except for localhost/127.x.x.x)
		if parsed.Scheme == "http" {
			return fmt.Errorf("redirect_uri[%d] must use https:// for non-localhost hosts", i)
		}
	}

	// Validate grant types
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	} else {
		// Validate that all grant types are supported
		supportedGrantTypes := map[string]bool{
			"authorization_code": true,
			"refresh_token":      true,
			"client_credentials": true,
		}

		for _, grantType := range req.GrantTypes {
			if !supportedGrantTypes[grantType] {
				return fmt.Errorf("unsupported grant_type: %s", grantType)
			}
		}
	}

	// Validate response types
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	} else {
		// Validate that all response types are supported
		supportedResponseTypes := map[string]bool{
			"code":     true,
			"token":    true,
			"id_token": true,
		}

		for _, responseType := range req.ResponseTypes {
			if !supportedResponseTypes[responseType] {
				return fmt.Errorf("unsupported response_type: %s", responseType)
			}
		}
	}

	// Validate application type
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	} else {
		supportedAppTypes := map[string]bool{
			"web":    true,
			"native": true,
			"spa":    true,
		}

		if !supportedAppTypes[req.ApplicationType] {
			return fmt.Errorf("unsupported application_type: %s", req.ApplicationType)
		}
	}

	// Validate signing algorithm if specified
	if req.IDTokenSignedResponseAlg != "" {
		supportedAlgs := map[string]bool{
			"RS256": true,
			"ES256": true,
		}

		if !supportedAlgs[req.IDTokenSignedResponseAlg] {
			return fmt.Errorf("unsupported id_token_signed_response_alg: %s (supported: RS256, ES256)", req.IDTokenSignedResponseAlg)
		}
	}

	// Validate that SPA and native clients use appropriate redirect URIs
	if req.ApplicationType == "spa" || req.ApplicationType == "native" {
		for _, uri := range req.RedirectURIs {
			parsed, err := url.Parse(uri)
			if err != nil {
				continue // Already validated above
			}

			if req.ApplicationType == "spa" && parsed.Scheme != "https" {
				return fmt.Errorf("SPA clients must use https:// redirect URIs, got: %s", uri)
			}

			if req.ApplicationType == "native" && parsed.Scheme != "http" && parsed.Scheme != "https" {
				return fmt.Errorf("native clients must use http:// or https:// redirect URIs, got: %s", uri)
			}
		}
	}

	return nil
}

func ptr[T any](v T) *T {
	return &v
}
