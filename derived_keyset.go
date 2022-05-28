package main

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type derivedKeyset struct {
	dbCurr [keySize]byte
	dbPrev [][keySize]byte
}

func newDerivedKeyset(currPassphrase string, prevPassphrases ...string) (*derivedKeyset, error) {
	ks := &derivedKeyset{}

	krdr := hkdf.New(sha256.New, []byte(currPassphrase), nil, nil)
	if _, err := io.ReadFull(krdr, ks.dbCurr[:]); err != nil {
		return nil, err
	}

	for _, p := range prevPassphrases {
		krdr := hkdf.New(sha256.New, []byte(p), nil, nil)
		var k [keySize]byte
		if _, err := io.ReadFull(krdr, k[:]); err != nil {
			return nil, err
		}
		ks.dbPrev = append(ks.dbPrev, k)
	}

	return ks, nil
}
