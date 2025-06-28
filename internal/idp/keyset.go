package idp

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lstoll/tinkrotate"
	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/oklog/run"
	"github.com/tink-crypto/tink-go/v2/aead"
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
	keysetIDCookie = "cookie"
	keysetIDOIDC   = "oidc"
)

var (
	cookieRotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         aead.XAES256GCM192BitNonceKeyTemplate(),
		PrimaryDuration:     durationpb.New(30 * 24 * time.Hour),
		PropagationTime:     durationpb.New(24 * time.Hour),
		PhaseOutDuration:    durationpb.New(7 * 24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
	oidcRotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         jwt.RS256_2048_F4_Key_Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
)

func initKeysets(ctx context.Context, db *sql.DB, g run.Group) (cookieKeyset, oidcKeyset *KeysetHandles, _ error) {
	store, err := tinkrotate.NewSQLStore(db, &tinkrotate.SQLStoreOptions{
		Dialect:   tinkrotate.SQLDialectSQLite,
		TableName: "tink_keysets",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create store: %w", err)
	}

	autoRotator, err := tinkrotate.NewAutoRotator(store, 1*time.Minute, &tinkrotate.AutoRotatorOpts{
		ProvisionPolicies: map[string]*tinkrotatev1.RotationPolicy{
			keysetIDCookie: cookieRotatePolicy,
			keysetIDOIDC:   oidcRotatePolicy,
		},
	}) // Create the Rotator instance using the proto policy
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create autoRotator: %w", err)
	}

	// need an initial run to provision keysets
	if err := autoRotator.RunOnce(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to run autoRotator: %w", err)
	}

	g.Add(func() error { autoRotator.Start(ctx); return nil }, func(_ error) { autoRotator.Stop() })

	return &KeysetHandles{keysetID: keysetIDCookie, store: store}, &KeysetHandles{keysetID: keysetIDOIDC, store: store}, nil
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
