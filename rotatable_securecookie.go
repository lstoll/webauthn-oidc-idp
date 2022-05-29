package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var _ sessions.Store = (*secureCookieManager)(nil)

type rotatableSecurecookie struct {
	KeyID string `json:"key_id"`

	HashKey  []byte `json:"hash_key"`
	BlockKey []byte `json:"block_key"`
	CsrfKey  []byte `json:"csrf_key"`
}

func (r *rotatableSecurecookie) ID() string {
	return r.KeyID
}
func (r *rotatableSecurecookie) Rotate(stage rotatorStage) error {
	// all symmetric, nothing to age out
	return nil
}

func newRotatableSecureCookie(enc *encryptor[[]byte]) (*rotatableSecurecookie, error) {
	scHashKey := make([]byte, 64)
	scEncryptKey := make([]byte, 32)
	csrfKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, scHashKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, scEncryptKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, csrfKey); err != nil {
		return nil, err
	}

	r := &rotatableSecurecookie{
		KeyID: uuid.NewString(),
	}
	var err error
	r.HashKey, err = enc.Encrypt(scHashKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting hash key: %w", err)
	}
	r.BlockKey, err = enc.Encrypt(scEncryptKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting encrypt key: %w", err)
	}
	r.CsrfKey, err = enc.Encrypt(csrfKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting csrf key: %w", err)
	}
	return r, nil
}

type secureCookieManager struct {
	rotator   *dbRotator[rotatableSecurecookie, *rotatableSecurecookie]
	encryptor *encryptor[[]byte]
}

func (s *secureCookieManager) buildStore(ctx context.Context) (sessions.Store, error) {
	var codecs []securecookie.Codec

	curr, err := s.rotator.GetCurrent(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting current key: %w", err)
	}
	prev, err := s.rotator.GetPrevious(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting previous keys: %w", err)
	}

	for _, k := range append([]*rotatableSecurecookie{curr}, prev...) {
		hk, err := s.encryptor.Decrypt(k.HashKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting hash key %s: %w", k.ID(), err)
		}
		bk, err := s.encryptor.Decrypt(k.BlockKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting block key %s: %w", k.ID(), err)
		}

		codecs = append(codecs, securecookie.New(hk, bk))

	}

	// we ignore the upcoming here. TODO - maybe make upcoming optional, this
	// doesn't need it, and the OIDC stuff doesn't strictly need it either.

	return &sessions.CookieStore{
		Codecs: codecs,
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 6 * 24 * 60 * 60, // 6 days, we keep keys around for about that.
		},
	}, nil
}

// Get should return a cached session.
func (s *secureCookieManager) Get(r *http.Request, name string) (*sessions.Session, error) {
	st, err := s.buildStore(context.Background())
	if err != nil {
		return nil, err
	}
	return st.Get(r, name)
}

// New should create and return a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
func (s *secureCookieManager) New(r *http.Request, name string) (*sessions.Session, error) {
	st, err := s.buildStore(context.Background())
	if err != nil {
		return nil, err
	}
	return st.New(r, name)
}

// Save should persist session to the underlying store implementation.
func (s *secureCookieManager) Save(r *http.Request, w http.ResponseWriter, sess *sessions.Session) error {
	st, err := s.buildStore(context.Background())
	if err != nil {
		return err
	}
	return st.Save(r, w, sess)
}

// CSRFHandler wraps a handler, adding csrf protection. It dynamically looks up
// the current key.
// It returns a function that can be used to wrap other things, ala csrf.Protect
func (s *secureCookieManager) CSRFHandler(ctx context.Context, eh *httpErrHandler) func(http.Handler) http.Handler {
	return func(wrap http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// note - when rotation happens, in-flight sessions will fail as the
			// csrf handler doesn't handle rotation
			// https://github.com/gorilla/csrf/issues/65
			// https://github.com/gorilla/csrf/issues/57

			curr, err := s.rotator.GetCurrent(r.Context())
			if err != nil {
				eh.Error(w, r, fmt.Errorf("getting current key: %w", err))
				return
			}

			ck, err := s.encryptor.Decrypt(curr.CsrfKey)
			if err != nil {
				eh.Error(w, r, fmt.Errorf("decrypting csrf key %s: %w", curr.ID(), err))
				return
			}

			csrf.Protect(ck)(wrap).ServeHTTP(w, r)
		})
	}
}
