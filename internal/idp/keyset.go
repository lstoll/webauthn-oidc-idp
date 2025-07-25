package idp

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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
	keysetIDOIDC = "oidc"
)

var (
	oidcRotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         jwt.RS256_2048_F4_Key_Template(),
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
			keysetIDOIDC: oidcRotatePolicy,
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

	return &KeysetHandles{keysetID: keysetIDOIDC, store: store}, nil
}

// KeysetHandles can retrieve handles for the given keyset from the DB.
type KeysetHandles struct {
	keysetID string
	store    tinkrotate.Store
}

// Handle returns a handle to the current keyset, including private keys
func (k *KeysetHandles) Handle(ctx context.Context) (*keyset.Handle, error) {
	return k.store.GetCurrentHandle(ctx, k.keysetID)
}

// PublicHandle returns a handle to the current keyset, only including public
// keys if they keyset supports this.
func (k *KeysetHandles) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	return k.store.GetPublicKeySetHandle(ctx, k.keysetID)
}
