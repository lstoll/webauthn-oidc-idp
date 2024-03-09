package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
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

var (
	KeysetOIDC = Keyset{
		Name:        "oidc",
		Template:    jwt.RS256_2048_F4_Key_Template(),
		RotateEvery: 24 * time.Hour,
	}
	KeysetCookie = Keyset{
		Name:        "cookie",
		Template:    aead.AES128GCMSIVKeyTemplate(),
		RotateEvery: 30 * 24 * time.Hour,
	}

	allKeysets = []Keyset{KeysetOIDC, KeysetCookie}
)

// KeysetHandles can retrieve handles for the given keyset from the DB.
type KeysetHandles struct {
	db     *DB
	keyset Keyset
}

// PublicHandle returns a handle to the current keyset, only including private
// keys
func (k *KeysetHandles) Handle(context.Context) (*keyset.Handle, error) {
	rdr := keyset.NewJSONReader(bytes.NewReader(k.db.GetKeyset(k.keyset).Keyset))
	h, err := insecurecleartextkeyset.Read(rdr)
	if err != nil {
		return nil, fmt.Errorf("parsing keyset from db: %w", err)
	}
	return h, nil
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

type KeysetManager struct {
	db *DB

	stopCh chan struct{}
}

func NewKeysetManager(db *DB) (*KeysetManager, error) {
	o := &KeysetManager{
		db:     db,
		stopCh: make(chan struct{}),
	}
	for _, ks := range allKeysets {
		if err := o.doRotate(ks); err != nil {
			return nil, fmt.Errorf("initial rotate for %s: %w", ks.Name, err)
		}
	}
	return o, nil
}

// PrivateHandle returns a handle to the current keyset, including private keys
func (o *KeysetManager) Handles(keyset Keyset) *KeysetHandles {
	return &KeysetHandles{db: o.db, keyset: keyset}
}

// Run synchronously runs a loop to rotate the keys in the DB as needed, and
// update handles on this manager instance.
func (o KeysetManager) Run() error {
	t := time.NewTicker(keysetRotateCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			for _, ks := range allKeysets {
				if err := o.doRotate(ks); err != nil {
					slog.Error("failed to rotate keyset", slog.String("keyset", ks.Name), logErr(err))
				}
			}
		case <-o.stopCh:
			return nil
		}
	}
}

func (o *KeysetManager) Interrupt(_ error) {
	o.stopCh <- struct{}{}
}

func (o *KeysetManager) doRotate(ks Keyset) error {
	cks := o.db.GetKeyset(ks)

	if time.Now().Before(cks.LastRotated.Add(ks.RotateEvery)) {
		// nothing to do, within rotation window
		return nil
	}

	if cks.Keyset == nil {
		slog.Info("provisioning new OIDC keyset")

		// new keyset. provision both current and upcoming key.
		h, err := keyset.NewHandle(ks.Template)
		if err != nil {
			return fmt.Errorf("creating new handle: %w", err)
		}

		mgr := keyset.NewManagerFromHandle(h)

		cks.UpcomingKeyID, err = mgr.Add(ks.Template)
		if err != nil {
			return fmt.Errorf("creating upcoming key: %w", err)
		}

		cks.LastRotated = time.Now()

		return o.writeKeyset(ks, cks, mgr)
	}

	slog.Info("rotating OIDC keyset", slog.Time("last-rotated", cks.LastRotated))

	// doing a normal rotation
	rdr := keyset.NewJSONReader(bytes.NewReader(cks.Keyset))
	h, err := insecurecleartextkeyset.Read(rdr)
	if err != nil {
		return fmt.Errorf("parsing keyset from db: %w", err)
	}

	mgr := keyset.NewManagerFromHandle(h)

	upcomingKID := cks.UpcomingKeyID
	currKID := h.KeysetInfo().PrimaryKeyId

	for _, ki := range h.KeysetInfo().KeyInfo {
		// remove all keys that aren't current or upcoming
		if ki.KeyId != upcomingKID || ki.KeyId != currKID {
			if err := mgr.Delete(ki.KeyId); err != nil {
				return fmt.Errorf("deleting key %d: %w", ki.KeyId, err)
			}
		}
	}

	if err := mgr.SetPrimary(upcomingKID); err != nil {
		return fmt.Errorf("setting primary key to %d: %w", upcomingKID, err)
	}

	cks.UpcomingKeyID, err = mgr.Add(ks.Template)
	if err != nil {
		return fmt.Errorf("creating new upcoming key: %w", err)
	}

	cks.LastRotated = time.Now()

	return o.writeKeyset(ks, cks, mgr)
}

// writeKeyset persists the updated handle and keyset info to the data store,
// and updates the private/public handles on this manager.
func (o *KeysetManager) writeKeyset(ks Keyset, dbks DBKeyset, km *keyset.Manager) error {
	h, err := km.Handle()
	if err != nil {
		return fmt.Errorf("getting handle from manager: %w", err)
	}

	buf := new(bytes.Buffer)
	wr := keyset.NewJSONWriter(buf)
	if err := insecurecleartextkeyset.Write(h, wr); err != nil {
		return fmt.Errorf("converting handle to JSON: %w", err)
	}
	dbks.Keyset = buf.Bytes()

	if err := o.db.PutKeyset(ks, dbks); err != nil {
		return fmt.Errorf("saving new keyset: %w", err)
	}

	return nil
}
