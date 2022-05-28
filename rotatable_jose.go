package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
)

const rsaKeyBits = 2048

var _ rotatable = (*rotatableRSAKey)(nil)
var _ crypto.Signer = (*rotatableRSAKey)(nil)
var _ jose.OpaqueSigner = (*JOSESigner)(nil)

// var _ jose.OpaqueVerifier = (*JOSESigner)(nil) // TODO - do we want this?

type rotatableRSAKey struct {
	KeyID      string `json:"key_id`
	PrivateKey []byte `json:"private,omitempty"`
	PublicKey  []byte `json:"public"`

	privparsed *rsa.PrivateKey `json:"-"`
	pubparsed  *rsa.PublicKey  `json:"-"`
}

func (r *rotatableRSAKey) ID() string {
	return r.KeyID
}

func (r *rotatableRSAKey) Initialize() error {
	r.KeyID = uuid.NewString()

	k, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("generating rsa key: %w", err)
	}

	r.PrivateKey = x509.MarshalPKCS1PrivateKey(k)
	r.privparsed = k
	r.PublicKey = x509.MarshalPKCS1PublicKey(&k.PublicKey)
	r.pubparsed = &k.PublicKey

	return nil
}

func (r *rotatableRSAKey) Rotate(stage rotatorStage) error {
	if stage == rotatorStagePrevious {
		r.privparsed = nil
		r.PrivateKey = nil
	}
	return nil
}

func (r *rotatableRSAKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if r.privparsed == nil {
		priv, err := x509.ParsePKCS1PrivateKey(r.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		r.privparsed = priv
	}
	return r.privparsed.Sign(rand, digest, opts)

}

func (r *rotatableRSAKey) Public() crypto.PublicKey {
	if r.pubparsed == nil {
		pub, err := x509.ParsePKCS1PublicKey(r.PublicKey)
		if err != nil {
			panic(err) // TODO - no real better way to deal with this here?
		}
		r.pubparsed = pub
	}
	return r.pubparsed
}

// JOSESigner implements jose.OpaqueSigner against the stored DB keys
type JOSESigner struct {
	rotator *dbRotator[rotatableRSAKey, *rotatableRSAKey]
}

// Public returns the public key of the current signing key.
func (j *JOSESigner) Public() *jose.JSONWebKey {
	ck, err := j.rotator.GetCurrent(context.Background())
	if err != nil {
		panic(err) // TODO?
	}

	return &jose.JSONWebKey{
		Key:       ck.Public(),
		Use:       "sig",
		KeyID:     ck.ID(),
		Algorithm: string(jose.RS256),
	}
}

// Algs returns the alg we support, RS256.
func (j *JOSESigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// SignPayload signs a payload with the current signing key using the given
// algorithm.
func (j *JOSESigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.RS256 {
		return nil, fmt.Errorf("only RS256 supported")
	}
	ck, err := j.rotator.GetCurrent(context.Background())
	if err != nil {
		return nil, fmt.Errorf("getting current signing key: %w", err)
	}

	return cryptosigner.Opaque(ck).SignPayload(payload, alg)
}

// PublicKeys returns a keyset of all public keys that should be considered
// valid for this signer
func (j *JOSESigner) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	curr, err := j.rotator.GetCurrent(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting previous keys: %w", err)
	}
	keys := []*rotatableRSAKey{curr}

	prev, err := j.rotator.GetPrevious(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting previous keys: %w", err)
	}
	keys = append(keys, prev...)

	upcoming, err := j.rotator.GetUpcoming(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting upcoming keys: %w", err)
	}
	keys = append(keys, upcoming...)

	ret := &jose.JSONWebKeySet{}

	for _, p := range keys {
		ret.Keys = append(ret.Keys, jose.JSONWebKey{
			Key:       p.Public(),
			KeyID:     p.ID(),
			Use:       "sig",
			Algorithm: string(jose.RS256),
		})
	}

	return ret, nil
}
