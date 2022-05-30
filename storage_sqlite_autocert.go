package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var _ autocert.Cache = (*autocertStore)(nil)

type autocertStore struct {
	db        *sql.DB
	encryptor *encryptor[[]byte]
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (a *autocertStore) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	if err := a.db.QueryRowContext(ctx, `select data from autocert_cache where key = $1`, key).Scan(&data); err != nil {
		if err == sql.ErrNoRows {
			return nil, autocert.ErrCacheMiss
		}
		return nil, fmt.Errorf("getting cached cert %s: %w", key, err)
	}
	dec, err := a.encryptor.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("decrypting data for key %s: %w", key, err)
	}
	return dec, nil
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (a *autocertStore) Put(ctx context.Context, key string, data []byte) error {
	enc, err := a.encryptor.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypting data: %w", err)
	}
	if _, err := a.db.ExecContext(ctx,
		`insert into autocert_cache (key, data, updated_at) values ($1, $2, $3)
		on conflict(key) do update set data=$3, updated_at=$5
		`, key, enc, time.Now(), enc, time.Now()); err != nil {
		return fmt.Errorf("putting data for %s: %w", key, err)
	}
	return nil
}

// Delete removes a certificate data from the cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (a *autocertStore) Delete(ctx context.Context, key string) error {
	if _, err := a.db.ExecContext(ctx,
		`delete from autocert_cache where key=$1
		`, key); err != nil {
		return fmt.Errorf("deleting autocert item %s: %w", key, err)
	}
	return nil
}
