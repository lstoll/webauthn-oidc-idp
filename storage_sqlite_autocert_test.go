package main

import (
	"context"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

func TestAutocertStore(t *testing.T) {
	ctx := context.Background()
	s := newTestStorage(t)
	encryptor := newEncryptor[[]byte](newKey())

	act := &autocertStore{
		db:        s.db,
		encryptor: encryptor,
	}

	_, err := act.Get(ctx, "key1")
	if err != autocert.ErrCacheMiss {
		t.Errorf("want %v, got %v", autocert.ErrCacheMiss, err)
	}

	if err := act.Put(ctx, "key1", []byte("hello")); err != nil {
		t.Fatal(err)
	}

	got, err := act.Get(ctx, "key1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("want hello, got: %s", string(got))
	}

	// should upsert
	if err := act.Put(ctx, "key1", []byte("hello2")); err != nil {
		t.Fatal(err)
	}

	got, err = act.Get(ctx, "key1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello2" {
		t.Errorf("want hello2, got: %s", string(got))
	}

	if err := act.Delete(ctx, "key1"); err != nil {
		t.Fatal(err)
	}

	_, err = act.Get(ctx, "key1")
	if err != autocert.ErrCacheMiss {
		t.Errorf("want %v, got %v", autocert.ErrCacheMiss, err)
	}

}
