package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

func TestRotatableOIDCSigner(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	const testUsage = "oidc-test"

	encryptor := newEncryptor[[]byte](newKey())

	dbr := &dbRotator[rotatableRSAKey, *rotatableRSAKey]{
		db:  s.db,
		log: logrus.New(),

		usage: testUsage,

		rotateInterval: 1 * time.Minute,
		maxAge:         10 * time.Minute,

		newFn: func() (*rotatableRSAKey, error) {
			return newRotatableRSAKey(encryptor)
		},
	}

	os := &oidcSigner{
		rotator:   dbr,
		encryptor: encryptor,
	}

	// seed the DB, invoke the creation methods
	if err := dbr.RotateIfNeeded(ctx); err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: &jose.JSONWebKey{
				Algorithm: string(jose.RS256),
				Key:       os,
				KeyID:     os.Public().KeyID,
				Use:       "sig",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := signer.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	signedser, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	jws, err := jose.ParseSigned(signedser)
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	pubs, err := os.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var (
		found bool
		key   jose.JSONWebKey
	)
	for _, pubk := range pubs.Keys {
		for _, sig := range jws.Signatures {
			if sig.Header.KeyID == pubk.KeyID {
				found = true
				key = pubk.Public()
			}
		}
	}
	if !found {
		t.Fatal("key not found in jwt headers")
	}

	payload, err := jws.Verify(key.Public())
	if err != nil {
		t.Fatalf("failed to verify JWT: %v", err)
	}

	if !bytes.Equal(payload, []byte("hello")) {
		t.Errorf("payload doesn't match")
	}

	// do a rotation, make sure it still verifies
	dbShift(t, ctx, dbr.db, -2*time.Minute)
	if err := dbr.RotateIfNeeded(ctx); err != nil {
		t.Fatalf("want no error rotating, got: %v", err)
	}

	pubs, err = os.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, pubk := range pubs.Keys {
		for _, sig := range jws.Signatures {
			if sig.Header.KeyID == pubk.KeyID {
				found = true
				key = pubk.Public()
			}
		}
	}
	if !found {
		t.Fatal("key not found in jwt headers")
	}

	payload, err = jws.Verify(key.Public())
	if err != nil {
		t.Fatalf("failed to verify JWT: %v", err)
	}

	if !bytes.Equal(payload, []byte("hello")) {
		t.Errorf("payload doesn't match")
	}
}
