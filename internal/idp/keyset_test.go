package idp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/memstore"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as"
)

func TestKeysetSignerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	store := memstore.New(insecurecleartext.Keeper)
	signer, authenticator, err := initKeysets(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, err := signer.Algorithms(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(algorithms) != 2 || algorithms[0] != jwt.RS256 || algorithms[1] != jwt.ES256 {
		t.Fatalf("algorithms = %v", algorithms)
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			now := time.Now()
			compact, err := signer.SignJWT(ctx, algorithm, oauth2as.JWTSigningInput{Payload: []byte(fmt.Sprintf(
				`{"sub":"test","iat":%d,"exp":%d}`, now.Unix(), now.Add(time.Hour).Unix()))})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := signer.VerifyJWT(ctx, compact, jwt.ValidationPolicy{
				IgnoreIssuer:      true,
				IgnoreAudiences:   true,
				AllowedAlgorithms: []jwt.Algorithm{algorithm},
				RequireIssuedAt:   true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if subject, err := verified.Subject(); err != nil || subject != "test" {
				t.Fatalf("subject = %q, %v", subject, err)
			}
		})
	}

	tag, err := authenticator.Authenticate([]byte("session-id"))
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify([]byte("session-id"), tag); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify([]byte("other"), tag); err == nil {
		t.Fatal("authenticator accepted the wrong message")
	}
}
