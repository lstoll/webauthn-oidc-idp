package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const (
	oidcRotateInterval      = 24 * time.Hour
	oidcRotateCheckInterval = 1 * time.Hour
)

var jwtKeyTemplate = jwt.RS256_2048_F4_Key_Template()

type OIDCKeysetManager struct {
	db *DB

	privHandle *keyset.Handle
	pubHandle  *keyset.Handle

	stopCh chan struct{}
}

func NewOIDCKeysetManager(db *DB) (*OIDCKeysetManager, error) {
	o := &OIDCKeysetManager{
		db: db,
	}
	if err := o.doRotate(); err != nil {
		return nil, fmt.Errorf("initial rotate: %w", err)
	}
	return o, nil
}

// PrivateHandle returns a handle to the current keyset, including private keys
func (o *OIDCKeysetManager) PrivateHandle() *keyset.Handle {
	return o.privHandle
}

// PublicHandle returns a handle to the current keyset, only including private
// keys
func (o *OIDCKeysetManager) PublicHandle() *keyset.Handle {
	return o.pubHandle
}

// Run synchronously runs a loop to rotate the keys in the DB as needed, and
// update handles on this manager instance.
func (o OIDCKeysetManager) Run() error {
	t := time.NewTicker(oidcRotateCheckInterval)
	for {
		select {
		case <-t.C:
			if err := o.doRotate(); err != nil {
				slog.Error("failed to rotate keyset", logErr(err))
			}
		case <-o.stopCh:
			return nil
		}
	}
}

func (o *OIDCKeysetManager) Interrupt(_ error) {
	o.stopCh <- struct{}{}
}

func (o *OIDCKeysetManager) doRotate() error {
	cks := o.db.GetOIDCKeyset()

	if time.Now().Before(cks.LastRotated.Add(oidcRotateInterval)) {
		// nothing to do, within rotation window
		return nil
	}

	if cks.Keyset == nil {
		slog.Info("provisioning new OIDC keyset")

		// new keyset. provision both current and upcoming key.
		h, err := keyset.NewHandle(jwtKeyTemplate)
		if err != nil {
			return fmt.Errorf("creating new handle: %w", err)
		}

		mgr := keyset.NewManagerFromHandle(h)

		cks.UpcomingKeyID, err = mgr.Add(jwtKeyTemplate)
		if err != nil {
			return fmt.Errorf("creating upcoming key: %w", err)
		}

		cks.LastRotated = time.Now()

		return o.writeKeyset(cks, mgr)
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

	cks.UpcomingKeyID, err = mgr.Add(jwtKeyTemplate)
	if err != nil {
		return fmt.Errorf("creating new upcoming key: %w", err)
	}

	cks.LastRotated = time.Now()

	return o.writeKeyset(cks, mgr)
}

// writeKeyset persists the updated handle and keyset info to the data store,
// and updates the private/public handles on this manager.
func (o *OIDCKeysetManager) writeKeyset(oks OIDCKeyset, km *keyset.Manager) error {
	h, err := km.Handle()
	if err != nil {
		return fmt.Errorf("getting handle from manager: %w", err)
	}
	pubh, err := h.Public()
	if err != nil {
		return fmt.Errorf("getting public handle: %w", err)
	}

	buf := new(bytes.Buffer)
	wr := keyset.NewJSONWriter(buf)
	if err := insecurecleartextkeyset.Write(h, wr); err != nil {
		return fmt.Errorf("converting handle to JSON: %w", err)
	}
	oks.Keyset = buf.Bytes()

	if err := o.db.PutOIDCKeyset(oks); err != nil {
		return fmt.Errorf("saving new keyset: %w", err)
	}

	o.privHandle = h
	o.pubHandle = pubh

	return nil
}
