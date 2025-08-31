package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	oidcjwt "github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oauth2as"
	"github.com/lstoll/tinkrotate"
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	tinkjwt "github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type Keyset struct {
	// Name of the keyset, used to refer to it in the store
	Name string
	// Template for new keys in this set
	Template *tink_go_proto.KeyTemplate
	// RotateEvery indicates how often we should rotate a new key in.
	RotateEvery time.Duration
}

const (
	keysetIDOIDC      = "oidc"
	keysetIDOIDCES256 = "oidc-es256"
)

var (
	oidcRotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         tinkjwt.RS256_2048_F4_Key_Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
	oidcES256RotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         tinkjwt.ES256Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
)

func initKeysets(ctx context.Context, db *sql.DB) (oidcKeyset *KeysetSigner, _ error) {
	store, err := tinkrotate.NewSQLStore(db, &tinkrotate.SQLStoreOptions{
		Dialect:   tinkrotate.SQLDialectSQLite,
		TableName: "tink_keysets",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	autoRotator, err := tinkrotate.NewAutoRotator(store, 10*time.Minute, &tinkrotate.AutoRotatorOpts{
		ProvisionPolicies: map[string]*tinkrotatev1.RotationPolicy{
			keysetIDOIDC:      oidcRotatePolicy,
			keysetIDOIDCES256: oidcES256RotatePolicy,
		},
	}) // Create the Rotator instance using the proto policy
	if err != nil {
		return nil, fmt.Errorf("failed to create autoRotator: %w", err)
	}

	// need an initial run to provision keysets
	if err := autoRotator.RunOnce(ctx); err != nil {
		return nil, fmt.Errorf("failed to run autoRotator: %w", err)
	}

	autoRotator.Start(ctx)

	return &KeysetSigner{algKeysets: map[oidcjwt.SigningAlg]string{
		oidcjwt.SigningAlgRS256: keysetIDOIDC,
		oidcjwt.SigningAlgES256: keysetIDOIDCES256,
	}, store: store}, nil
}

var _ oauth2as.AlgorithmSigner = (*KeysetSigner)(nil)

// KeysetSigner can retrieve handles for the given keyset from the DB.
type KeysetSigner struct {
	// algKeysets maps an algorithm to the keyset ID for that algorithm.
	algKeysets map[oidcjwt.SigningAlg]string
	// store is the store for the keysets.
	store tinkrotate.Store
}

func (k *KeysetSigner) SignWithAlgorithm(ctx context.Context, alg, typHdr string, payload []byte) (string, error) {
	id, ok := k.algKeysets[oidcjwt.SigningAlg(alg)]
	if !ok {
		return "", fmt.Errorf("no keyset for algorithm %s", alg)
	}
	h, err := k.store.GetCurrentHandle(ctx, id)
	if err != nil {
		return "", fmt.Errorf("get current handle: %w", err)
	}

	signer, err := tinkjwt.NewSigner(h)
	if err != nil {
		return "", fmt.Errorf("new signer: %w", err)
	}

	var th *string
	if typHdr != "" {
		th = &typHdr
	}

	rawJWT, err := tinkjwt.NewRawJWTFromJSON(th, payload)
	if err != nil {
		return "", fmt.Errorf("new raw jwt: %w", err)
	}

	return signer.SignAndEncode(rawJWT)
}

// SupportedAlgorithms returns the list of algorithms supported by this
// signer.
func (k *KeysetSigner) SupportedAlgorithms() []string {
	var algs []string
	for alg := range k.algKeysets {
		algs = append(algs, string(alg))
	}
	return algs
}

func (k *KeysetSigner) GetKeysByKID(ctx context.Context, kid string) ([]oidcjwt.PublicKey, error) {
	jwks, err := k.jwks(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting JWKS: %w", err)
	}
	return jwks.GetKeysByKID(ctx, kid)
}

func (k *KeysetSigner) GetKeys(ctx context.Context) ([]oidcjwt.PublicKey, error) {
	jwks, err := k.jwks(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting JWKS: %w", err)
	}
	return jwks.GetKeys(ctx)
}

func (k *KeysetSigner) jwks(ctx context.Context) (*oidcjwt.StaticKeyset, error) {
	mergejwksm := map[string]any{
		"keys": []any{},
	}

	for alg, id := range k.algKeysets {
		h, err := k.store.GetCurrentHandle(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("getting handle for %s: %w", alg, err)
		}

		pub, err := h.Public()
		if err != nil {
			return nil, fmt.Errorf("getting public handle for %s: %w", alg, err)
		}

		jwks, err := tinkjwt.JWKSetFromPublicKeysetHandle(pub)
		if err != nil {
			return nil, fmt.Errorf("getting JWKS for %s: %w", alg, err)
		}

		jwksm := make(map[string]any)
		if err := json.Unmarshal(jwks, &jwksm); err != nil {
			return nil, fmt.Errorf("unmarshalling JWKS for %s: %w", alg, err)
		}

		for _, k := range jwksm["keys"].([]any) {
			mergejwksm["keys"] = append(mergejwksm["keys"].([]any), k)
		}
	}

	mergejwks, err := json.Marshal(mergejwksm)
	if err != nil {
		return nil, fmt.Errorf("marshalling merged JWKS: %w", err)
	}

	return oidcjwt.NewStaticKeysetFromJWKS(mergejwks)
}
