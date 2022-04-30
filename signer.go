package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/lstoll/awskms"
	"github.com/lstoll/idp/internal/config"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/signer"
)

func newSignerFromConfig(ctx context.Context, cfg *config.Config) (core.Signer, discovery.KeySource, error) {
	switch cfg.OIDCSigner.Type {
	case "static":
		privPem, _ := pem.Decode([]byte(cfg.OIDCSigner.StaticSigner.KeyPEM))
		if privPem.Type != "RSA PRIVATE KEY" {
			return nil, nil, fmt.Errorf("key should be RSA PRIVATE KEY, but got: %s", privPem.Type)
		}

		parsed, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing private key: %v", err)
		}

		jwts, err := signer.NewFromCrypto(parsed, cfg.OIDCSigner.StaticSigner.KeyID)
		if err != nil {
			log.Fatalf("creating JWT signer from crypto.Signer: %v", err)
		}

		return jwts, jwts, nil
	case "kms":
		awscfg, err := cfg.AWSConfig()
		if err != nil {
			return nil, nil, err
		}
		kmscli := kms.New(awscfg)

		s, err := awskms.NewSigner(ctx, kmscli, cfg.OIDCSigner.KMSSigner.ARN)
		if err != nil {
			return nil, nil, fmt.Errorf("creating KMS signer: %v", err)
		}

		// hash the key ID so we aren't leaking the ARN
		kh := sha256.New()
		if _, err := kh.Write([]byte(cfg.OIDCSigner.KMSSigner.ARN)); err != nil {
			log.Fatal(err)
		}
		jwtKeyID := hex.EncodeToString(kh.Sum(nil))[0:16]

		jwts, err := signer.NewFromCrypto(s, jwtKeyID)
		if err != nil {
			log.Fatalf("creating JWT signer from crypto.Signer: %v", err)
		}

		return jwts, jwts, nil
	default:
		return nil, nil, fmt.Errorf("invalid signer type %s", cfg.OIDCSigner.Type)
	}
}
