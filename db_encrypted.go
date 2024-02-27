package main

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"

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

	encryptedMagicJSON = "ENJ\x00"
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
		return nil, fmt.Errorf("creating nonce: %w", err)
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
		return fmt.Errorf("nil source")
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
	return nil, fmt.Errorf("field failed to decrypt, missing keys?")
}

type encryptor[T any] struct {
	// EncryptionKey is used to encrypt and decrypt data
	EncryptionKey [keySize]byte
	// AdditionalKeys are also checked for decryption, to allow for rotation
	AdditionalKeys [][keySize]byte
	// AllowUnecryptedReads will handle un-encrypted data in the database
	// transparently by just passing it through. by default, this will cause an
	// error
	AllowUnencryptedReads bool
}

func newEncryptor[T any](key [keySize]byte, additionalKeys ...[keySize]byte) *encryptor[T] {
	gob.Register(*new(T))
	return &encryptor[T]{
		EncryptionKey:  key,
		AdditionalKeys: additionalKeys,
	}
}

func (e *encryptor[T]) Encrypt(data T) ([]byte, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling data: %v", err)
	}

	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("creating nonce: %w", err)
	}

	sealed := secretbox.Seal(nonce[:], b, &nonce, &e.EncryptionKey)

	return append([]byte(encryptedMagicJSON), sealed...), nil
}

func (e *encryptor[T]) Decrypt(data []byte) (T, error) {
	var nilt T

	if !bytes.HasPrefix(data, []byte(encryptedMagicJSON)) {
		return nilt, fmt.Errorf("incorrect magic prefix")
	}
	b := data[4:]

	for _, k := range append([][keySize]byte{e.EncryptionKey}, e.AdditionalKeys...) {
		var decryptNonce [nonceSize]byte
		copy(decryptNonce[:], b[:nonceSize])
		db, ok := secretbox.Open(nil, b[nonceSize:], &decryptNonce, &k)
		if ok {
			newt := *new(T)
			if err := json.Unmarshal(db, &newt); err != nil {
				return nilt, fmt.Errorf("unmarshaling data: %w", err)
			}
			return newt, nil
		}
	}
	return nilt, fmt.Errorf("field failed to decrypt, missing keys?")
}
