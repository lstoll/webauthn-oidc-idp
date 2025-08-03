package idp

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lstoll/oauth2as"
	"github.com/lstoll/tinkrotate"
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
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
		KeyTemplate:         jwt.RS256_2048_F4_Key_Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
	oidcES256RotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         jwt.ES256Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
)

func initKeysets(ctx context.Context, db *sql.DB) (oidcKeyset *KeysetHandles, _ error) {
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

	return &KeysetHandles{algKeysets: map[oauth2as.SigningAlg]string{
		oauth2as.SigningAlgRS256: keysetIDOIDC,
		oauth2as.SigningAlgES256: keysetIDOIDCES256,
	}, store: store}, nil
}

var _ oauth2as.AlgKeysets = (*KeysetHandles)(nil)

// KeysetHandles can retrieve handles for the given keyset from the DB.
type KeysetHandles struct {
	// algKeysets maps an algorithm to the keyset ID for that algorithm.
	algKeysets map[oauth2as.SigningAlg]string
	// store is the store for the keysets.
	store tinkrotate.Store
}

func (k *KeysetHandles) HandleFor(alg oauth2as.SigningAlg) (*keyset.Handle, error) {
	id, ok := k.algKeysets[alg]
	if !ok {
		return nil, fmt.Errorf("no keyset for algorithm %s", alg)
	}
	return k.store.GetCurrentHandle(context.TODO(), id)
}

func (k *KeysetHandles) SupportedAlgorithms() []oauth2as.SigningAlg {
	var algs []oauth2as.SigningAlg
	for alg := range k.algKeysets {
		algs = append(algs, alg)
	}
	return algs
}
