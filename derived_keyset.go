package main

import (
	"crypto/sha256"
	"io"

	"github.com/lstoll/cookiesession"
	"golang.org/x/crypto/hkdf"
)

const (
	// keySize is the length of secretbox's key array. We should always use a key
	// that matches this.
	keySize = 32
)

type derivedKeyset struct {
	dbCurr [keySize]byte
	dbPrev [][keySize]byte

	webSessCurr   []byte
	webSessPrev   [][]byte
	oidcmSessCurr []byte
	oidcmSessPrev [][]byte
}

func newDerivedKeyset(currPassphrase string, prevPassphrases ...string) (*derivedKeyset, error) {
	ks := &derivedKeyset{}

	// remember that derivation order is important, only the same part of the
	// reader has the same data consistently. so if we remove things, we need to
	// discard that len. if we add, always at the end.

	krdr := hkdf.New(sha256.New, []byte(currPassphrase), nil, nil)

	if _, err := io.ReadFull(krdr, ks.dbCurr[:]); err != nil {
		return nil, err
	}

	ks.webSessCurr = make([]byte, cookiesession.KeySizeAES128)
	if _, err := io.ReadFull(krdr, ks.webSessCurr); err != nil {
		return nil, err
	}

	ks.oidcmSessCurr = make([]byte, cookiesession.KeySizeAES128)
	if _, err := io.ReadFull(krdr, ks.oidcmSessCurr); err != nil {
		return nil, err
	}

	for _, p := range prevPassphrases {
		krdr := hkdf.New(sha256.New, []byte(p), nil, nil)
		var k [keySize]byte
		if _, err := io.ReadFull(krdr, k[:]); err != nil {
			return nil, err
		}
		ks.dbPrev = append(ks.dbPrev, k)

		wsc := make([]byte, cookiesession.KeySizeAES128)
		if _, err := io.ReadFull(krdr, wsc); err != nil {
			return nil, err
		}
		ks.webSessPrev = append(ks.webSessPrev, wsc)

		osc := make([]byte, cookiesession.KeySizeAES128)
		if _, err := io.ReadFull(krdr, osc); err != nil {
			return nil, err
		}
		ks.oidcmSessPrev = append(ks.oidcmSessPrev, osc)
	}

	return ks, nil
}
