package storage_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/passidp/internal/storage"
)

func TestDPoPReplayStore(t *testing.T) {
	ctx := context.Background()
	sqlDB := storage.OpenTest(t)
	store := storage.NewDPoPReplayStore(sqlDB)
	until := time.Now().Add(time.Minute)

	if err := store.CheckAndRecord(ctx, "thumb", "jti-1", until); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := store.CheckAndRecord(ctx, "thumb", "jti-1", until); !errors.Is(err, dpop.ErrProofReplay) {
		t.Fatalf("replay error = %v, want ErrProofReplay", err)
	}
	if err := store.CheckAndRecord(ctx, "thumb", "jti-2", until); err != nil {
		t.Fatalf("different jti rejected: %v", err)
	}
	if err := store.CheckAndRecord(ctx, "other-thumb", "jti-1", until); err != nil {
		t.Fatalf("different thumbprint rejected: %v", err)
	}
}

func TestDPoPReplayStoreExpiry(t *testing.T) {
	ctx := context.Background()
	sqlDB := storage.OpenTest(t)
	store := storage.NewDPoPReplayStore(sqlDB)
	until := time.Now().Add(time.Minute)

	if err := store.CheckAndRecord(ctx, "thumb", "jti", until); err != nil {
		t.Fatalf("first record: %v", err)
	}

	_, err := sqlDB.Exec(`UPDATE dpop_replay SET until = ?`, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("backdate replay record: %v", err)
	}

	if err := store.CheckAndRecord(ctx, "thumb", "jti", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reuse after expiry: %v", err)
	}

	deleted, err := store.GarbageCollectExpiredProofs()
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("gc deleted %d still-valid records, want 0", deleted)
	}

	_, err = sqlDB.Exec(`UPDATE dpop_replay SET until = ?`, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatalf("backdate replay record: %v", err)
	}
	deleted, err = store.GarbageCollectExpiredProofs()
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("gc deleted %d, want 1", deleted)
	}
}

func TestDPoPReplayStoreCanceledContext(t *testing.T) {
	store := storage.NewDPoPReplayStore(storage.OpenTest(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.CheckAndRecord(ctx, "thumb", "jti", time.Now().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}
}

func TestDPoPReplayStoreConcurrent(t *testing.T) {
	ctx := context.Background()
	store := storage.NewDPoPReplayStore(storage.OpenTest(t))
	until := time.Now().Add(time.Minute)

	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			results <- store.CheckAndRecord(ctx, "thumb", "concurrent", until)
		})
	}
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, dpop.ErrProofReplay) {
			t.Fatalf("concurrent record: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want 1", successes)
	}
}
