package storage_test

import (
	"context"
	"testing"
	"time"

	"lds.li/passidp/internal/storage"
)

func TestSessionKVGC(t *testing.T) {
	sqlDB := storage.OpenTest(t)
	kv, err := storage.NewSessionKV(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	expiredKey := "expired"
	if err := kv.Set(ctx, expiredKey, time.Now().Add(-time.Hour), []byte("expired")); err != nil {
		t.Fatalf("set expired session: %v", err)
	}
	if err := kv.Set(ctx, "valid", time.Now().Add(time.Hour), []byte("valid")); err != nil {
		t.Fatalf("set valid session: %v", err)
	}

	deleted, err := kv.GC(ctx)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted session, got %d", deleted)
	}

	_, found, err := kv.Get(ctx, "valid")
	if err != nil {
		t.Fatalf("get valid session: %v", err)
	}
	if !found {
		t.Fatal("expected valid session to remain")
	}
}
