package idp

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"lds.li/keyset"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/session"
)

const (
	keysetIDOIDCRS256  = "oidc-rs256"
	keysetIDOIDCES256  = "oidc-es256"
	keysetIDSessionMAC = "session-mac"
)

var (
	oidcPolicy = keyset.Policy{
		Primary:   24 * time.Hour,
		Propagate: 6 * time.Hour,
		PhaseOut:  24 * time.Hour,
	}
	sessionMACPolicy = keyset.Policy{
		Primary:   24 * time.Hour,
		Propagate: 6 * time.Hour,
		PhaseOut:  24 * time.Hour,
	}
)

func initKeysets(ctx context.Context, store keyset.AdminStore) (*KeysetSigner, session.Authenticator, error) {
	rotator, err := keyset.NewRotator(store,
		keyset.WithInterval(10*time.Minute),
		keyset.WithEnsure(map[string]keyset.Spec{
			keysetIDOIDCRS256:  {Algorithm: keyset.RSAPKCS1v15_2048_SHA256, Policy: oidcPolicy},
			keysetIDOIDCES256:  {Algorithm: keyset.ECDSAP256SHA256, Policy: oidcPolicy},
			keysetIDSessionMAC: {Algorithm: keyset.HMACSHA256, Policy: sessionMACPolicy},
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create keyset rotator: %w", err)
	}
	if err := rotator.Once(ctx); err != nil {
		return nil, nil, fmt.Errorf("provision keysets: %w", err)
	}
	if err := rotator.Run(ctx); err != nil {
		return nil, nil, fmt.Errorf("start keyset rotator: %w", err)
	}

	client, err := keyset.NewClient(store, keyset.WithTTL(5*time.Minute))
	if err != nil {
		return nil, nil, fmt.Errorf("create keyset client: %w", err)
	}
	return &KeysetSigner{client: client}, &keysetSessionAuthenticator{client: client}, nil
}

type KeysetSigner struct {
	client *keyset.Client
}

var (
	_ oauth2as.JWTSigner   = (*KeysetSigner)(nil)
	_ oauth2as.JWTVerifier = (*KeysetSigner)(nil)
)

func (k *KeysetSigner) Algorithms(context.Context) ([]jwt.Algorithm, error) {
	return []jwt.Algorithm{jwt.RS256, jwt.ES256}, nil
}

func (k *KeysetSigner) SignJWT(ctx context.Context, algorithm jwt.Algorithm, input oauth2as.JWTSigningInput) (string, error) {
	var keysetID string
	switch algorithm {
	case jwt.RS256:
		keysetID = keysetIDOIDCRS256
	case jwt.ES256:
		keysetID = keysetIDOIDCES256
	default:
		return "", fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
	signer, err := k.client.Signer(ctx, keysetID)
	if err != nil {
		return "", fmt.Errorf("load signing keyset: %w", err)
	}
	local, err := oauth2as.NewLocalJWTSigner(oauth2as.LocalJWTSignerConfig{
		SigningKeys: []oauth2as.SigningKey{{Algorithm: algorithm, Key: signer}},
	})
	if err != nil {
		return "", fmt.Errorf("create JWT signer: %w", err)
	}
	return local.SignJWT(ctx, algorithm, input)
}

func (k *KeysetSigner) VerifyJWT(ctx context.Context, compact string, policy jwt.ValidationPolicy) (*jwt.VerifiedJWT, error) {
	encoded, err := k.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := jwt.ParseJWKSet(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return keys.VerifyJWT(compact, policy)
}

func (k *KeysetSigner) JWKS(ctx context.Context) ([]byte, error) {
	set := jose.JSONWebKeySet{}
	keysets := []struct {
		id        string
		algorithm string
	}{
		{id: keysetIDOIDCRS256, algorithm: string(jwt.RS256)},
		{id: keysetIDOIDCES256, algorithm: string(jwt.ES256)},
	}
	for _, spec := range keysets {
		public, err := k.client.Public(ctx, spec.id)
		if err != nil {
			return nil, fmt.Errorf("load public signing keyset %q: %w", spec.id, err)
		}
		if _, err := public.Verifier(); err != nil {
			return nil, fmt.Errorf("validate public signing keyset %q: %w", spec.id, err)
		}
		for _, source := range public.Keys {
			if source.State == "disabled" {
				continue
			}
			publicKey, err := x509.ParsePKIXPublicKey(source.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("parse public key %d from keyset %q: %w", source.ID, spec.id, err)
			}
			key := jose.JSONWebKey{Key: publicKey, Algorithm: spec.algorithm, Use: "sig"}
			thumbprint, err := key.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("calculate JWK thumbprint for key %d from keyset %q: %w", source.ID, spec.id, err)
			}
			key.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)
			set.Keys = append(set.Keys, key)
		}
	}
	return json.Marshal(set)
}

type keysetSessionAuthenticator struct {
	client *keyset.Client
}

func (a *keysetSessionAuthenticator) Authenticate(message []byte) ([]byte, error) {
	mac, err := a.client.MAC(context.Background(), keysetIDSessionMAC)
	if err != nil {
		return nil, err
	}
	return mac.Compute(message)
}

func (a *keysetSessionAuthenticator) Verify(message, authenticator []byte) error {
	mac, err := a.client.MAC(context.Background(), keysetIDSessionMAC)
	if err != nil {
		return err
	}
	return mac.Verify(authenticator, message)
}
