package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/pardot/oidc/core"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
)

const rsaKeyBits = 2048

var _ rotatable = (*rotatableRSAKey)(nil)
var _ crypto.Signer = (*rotatableRSAKey)(nil)
var _ core.Signer = (*oidcSigner)(nil)

// var _ jose.OpaqueVerifier = (*JOSESigner)(nil) // TODO - do we want this?

type rotatableRSAKey struct {
	KeyID      string `json:"key_id`
	PrivateKey []byte `json:"private,omitempty"`
	PublicKey  []byte `json:"public"`

	privparsed *rsa.PrivateKey    `json:"-"`
	pubparsed  *rsa.PublicKey     `json:"-"`
	encryptor  *encryptor[[]byte] `json:"-"`
}

func (r *rotatableRSAKey) ID() string {
	return r.KeyID
}

func newRotatableRSAKey(enc *encryptor[[]byte]) (*rotatableRSAKey, error) {
	r := &rotatableRSAKey{
		encryptor: enc,
	}

	r.KeyID = uuid.NewString()

	k, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating rsa key: %w", err)
	}

	pk, err := r.encryptor.Encrypt(x509.MarshalPKCS1PrivateKey(k))
	if err != nil {
		return nil, fmt.Errorf("encrypting private key: %w", err)
	}
	r.PrivateKey = pk
	r.privparsed = k
	r.PublicKey = x509.MarshalPKCS1PublicKey(&k.PublicKey)
	r.pubparsed = &k.PublicKey

	return r, nil
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
		pdec, err := r.encryptor.Decrypt(r.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting private key: %v", err)
		}
		priv, err := x509.ParsePKCS1PrivateKey(pdec)
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

// oidcSigner implements jose.OpaqueSigner against the stored DB keys
type oidcSigner struct {
	rotator   *dbRotator[rotatableRSAKey, *rotatableRSAKey]
	encryptor *encryptor[[]byte]
}

func (o *oidcSigner) SignerAlg(ctx context.Context) (jose.SignatureAlgorithm, error) {
	return jose.RS256, nil
}

func (o *oidcSigner) Sign(ctx context.Context, data []byte) (signed []byte, err error) {
	ck, err := o.rotator.GetCurrent(context.Background())
	if err != nil {
		return nil, fmt.Errorf("getting current signing key: %w", err)
	}
	ck.encryptor = o.encryptor

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: &jose.JSONWebKey{
				Algorithm: string(jose.RS256),
				Key:       cryptosigner.Opaque(ck),
				KeyID:     ck.KeyID,
				Use:       "sig",
			},
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("signing: %v", err)
	}

	sg, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	ser, err := sg.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("serializing signed data: %v", err)
	}
	return []byte(ser), nil
}

func (o *oidcSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	pubs, err := o.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %v", err)
	}

	var (
		found bool
		key   jose.JSONWebKey
	)
	for _, pubk := range pubs.Keys {
		for _, sig := range jws.Signatures {
			if sig.Header.KeyID == pubk.KeyID {
				found = true
				key = pubk.Public()
			}
		}
	}
	if !found {
		return nil, errors.New("failed to find matching signing key")
	}

	payload, err = jws.Verify(key.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %v", err)
	}

	return payload, nil
}

// PublicKeys returns a keyset of all public keys that should be considered
// valid for this signer
func (o *oidcSigner) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	curr, err := o.rotator.GetCurrent(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting previous keys: %w", err)
	}
	keys := []*rotatableRSAKey{curr}

	prev, err := o.rotator.GetPrevious(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting previous keys: %w", err)
	}
	keys = append(keys, prev...)

	upcoming, err := o.rotator.GetUpcoming(ctx)
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
