package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

type testEncValue struct {
	Hello string `json:"hello"`
}

func TestEncryptedDB(t *testing.T) {
	k := newKey()

	plaintext := testEncValue{
		Hello: "world",
	}

	fenc := newFieldEncryptor(k, plaintext)

	b, err := fenc.Value()
	if err != nil {
		t.Fatal(err)
	}

	fdec := newFieldDecryptor[testEncValue](k)

	if err := fdec.Scan(b); err != nil {
		t.Fatal(err)
	}

	if fdec.Plaintext.Hello != plaintext.Hello {
		t.Errorf("want %s got %s", fdec.Plaintext.Hello, plaintext.Hello)
	}
}

func TestEncryptor(t *testing.T) {
	benc := newEncryptor[[]byte](newKey())

	dat := []byte("hello")

	enc, err := benc.Encrypt(dat)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := benc.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dec, dat) {
		t.Errorf("round trip failed")
	}
}

func newKey() [keySize]byte {
	var k [keySize]byte
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		panic(err)
	}
	return k
}
