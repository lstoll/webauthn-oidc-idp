package main

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// keySize is the length of secretbox's key array. We should always use a key
	// that matches this.
	keySize = 32
	// nonceSize is the length of the nonce we use for secretbox
	nonceSize = 24
	// encryptedMagic indicates that this is a sensitive value in the DB.
	encryptedMagic = "ENC\x00"
)

type fieldEncryptor struct {
	// EncryptionKey is used to encrypt and decrypt data
	EncryptionKey [keySize]byte
	// Plaintext value that we are wrapping. Encoded from.
	Plaintext any
}

func newFieldEncryptor(key [keySize]byte, plaintext any) *fieldEncryptor {
	return &fieldEncryptor{
		EncryptionKey: key,
		Plaintext:     plaintext,
	}
}

func (e *fieldEncryptor) Value() (driver.Value, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, errors.Wrap(err, "Failed to create nonce")
	}

	b, err := json.Marshal(e.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("marshaling Plaintext: %w", err)
	}

	sealed := secretbox.Seal(nonce[:], b, &nonce, &e.EncryptionKey)

	return append([]byte(encryptedMagic), sealed...), nil
}

type fieldDecryptor[T any] struct {
	// EncryptionKey is used to encrypt and decrypt data
	EncryptionKey [keySize]byte
	// AdditionalKeys are also checked for decryption, to allow for rotation
	AdditionalKeys [][keySize]byte
	// AllowUnecryptedReads will handle un-encrypted data in the database
	// transparently by just passing it through. by default, this will cause an
	// error
	AllowUnencryptedReads bool
	// Plaintext value that we are wrapping. Decoded to.
	Plaintext T
}

func newFieldDecryptor[T any](key [keySize]byte, additionalKeys ...[keySize]byte) *fieldDecryptor[T] {
	return &fieldDecryptor[T]{
		EncryptionKey:  key,
		AdditionalKeys: additionalKeys,
	}
}

func (e *fieldDecryptor[T]) Scan(src interface{}) error {
	if src == nil {
		return errors.New("nil source")
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("expected src []byte got %T", src)
	}

	// if we have the encrypted magic, try all the decryption keys and fail if
	// it doesn't decode
	if bytes.HasPrefix(b, []byte(encryptedMagic)) {
		db, err := e.decrypt(b[4:])
		if err != nil {
			return err
		}
		b = db
	} else if !e.AllowUnencryptedReads { // if we don't have the magic and don't have unenc, fail
		return fmt.Errorf("field does not have magic number, and unencrytped fields not allowed")
	}

	// just pass the raw data through
	if err := json.Unmarshal(b, &e.Plaintext); err != nil {
		return fmt.Errorf("unmarshaling field: %w", err)
	}
	return nil
}

func (e *fieldDecryptor[T]) decrypt(b []byte) ([]byte, error) {
	for _, k := range append([][keySize]byte{e.EncryptionKey}, e.AdditionalKeys...) {
		var decryptNonce [nonceSize]byte
		copy(decryptNonce[:], b[:nonceSize])
		db, ok := secretbox.Open(nil, b[nonceSize:], &decryptNonce, &k)
		if ok {
			return db, nil
		}
	}
	return nil, errors.New("field failed to decrypt, missing keys?")
}
