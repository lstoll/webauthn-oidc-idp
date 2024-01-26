package main

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestRotatableOIDCSigner(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)

	const testUsage = "oidc-test"

	encryptor := newEncryptor[[]byte](newKey())

	dbr := &dbRotator[rotatableRSAKey, *rotatableRSAKey]{
		db:             s.db,
		usage:          testUsage,
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

	signed, err := os.Sign(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	payload, err := os.VerifySignature(ctx, string(signed))
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

	payload, err = os.VerifySignature(ctx, string(signed))
	if err != nil {
		t.Fatalf("failed to verify JWT: %v", err)
	}

	if !bytes.Equal(payload, []byte("hello")) {
		t.Errorf("payload doesn't match")
	}
}
