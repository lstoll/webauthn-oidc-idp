package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lstoll/tinkrotate"
	"github.com/oklog/run"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

const keysetRotateCheckInterval = 1 * time.Hour

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
	cookieRotatePolicy = tinkrotate.RotationPolicy{
		KeyTemplate:         aead.XAES256GCM192BitNonceKeyTemplate(),
		PrimaryDuration:     30 * 24 * time.Hour,
		PropagationTime:     24 * time.Hour,
		PhaseOutDuration:    7 * 24 * time.Hour,
		DeletionGracePeriod: 0,
	}
	oidcRotatePolicy = tinkrotate.RotationPolicy{
		KeyTemplate:         jwt.RS256_2048_F4_Key_Template(),
		PrimaryDuration:     24 * time.Hour,
		PropagationTime:     6 * time.Hour,
		PhaseOutDuration:    24 * time.Hour,
		DeletionGracePeriod: 0,
	}
)

func initKeysets(ctx context.Context, db *sql.DB, g run.Group) (cookieKeyset, oidcKeyset *KeysetHandles, _ error) {
	cookieStore, err := tinkrotate.NewSQLStore(db, keysetIDCookie)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cookie keyset store: %w", err)
	}
	cookieRotator, err := tinkrotate.NewRotator(cookieRotatePolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cookie rotator: %w", err)
	}
	cookieAutoRotator, err := tinkrotate.NewAutoRotator(cookieStore, cookieRotator, 10*time.Minute)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cookie rotator: %w", err)
	}
	if err := cookieAutoRotator.RunOnce(ctx); err != nil {
		return nil, nil, fmt.Errorf("running cookie rotator: %w", err)
	}
	g.Add(func() error { cookieAutoRotator.Start(ctx); return nil }, func(_ error) { cookieAutoRotator.Stop() })

	oidcStore, err := tinkrotate.NewSQLStore(db, keysetIDOIDC)
	if err != nil {
		return nil, nil, fmt.Errorf("creating oidc keyset store: %w", err)
	}
	oidcRotator, err := tinkrotate.NewRotator(oidcRotatePolicy)
	if err != nil {
		return nil, nil, fmt.Errorf("creating oidc rotator: %w", err)
	}
	oidcAutoRotator, err := tinkrotate.NewAutoRotator(oidcStore, oidcRotator, 10*time.Minute)
	if err != nil {
		return nil, nil, fmt.Errorf("creating oidc rotator: %w", err)
	}
	if err := oidcAutoRotator.RunOnce(ctx); err != nil {
		return nil, nil, fmt.Errorf("running oidc rotator: %w", err)
	}
	g.Add(func() error { oidcAutoRotator.Start(ctx); return nil }, func(_ error) { oidcAutoRotator.Stop() })

	return &KeysetHandles{autoRotator: cookieAutoRotator}, &KeysetHandles{autoRotator: oidcAutoRotator}, nil
}

// KeysetHandles can retrieve handles for the given keyset from the DB.
type KeysetHandles struct {
	autoRotator *tinkrotate.AutoRotator
}

// PublicHandle returns a handle to the current keyset, only including private
// keys
func (k *KeysetHandles) Handle(ctx context.Context) (*keyset.Handle, error) {
	return k.autoRotator.GetCurrentHandle(ctx)
}

// PublicHandle returns a handle to the current keyset, only including public
// keys if they keyset supports this.
func (k *KeysetHandles) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	h, err := k.Handle(ctx)
	if err != nil {
		return nil, err
	}
	ph, err := h.Public()
	if err != nil {
		return nil, err
	}
	return ph, nil
}
