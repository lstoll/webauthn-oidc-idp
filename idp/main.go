package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/apex/gateway"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/lstoll/awskms"
	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/signer"
)

var (
	// DefaultHTTPGetAddress Default Address
	DefaultHTTPGetAddress = "https://checkip.amazonaws.com"

	// ErrNoIP No IP found in response
	ErrNoIP = errors.New("No IP in HTTP response")

	// ErrNon200Response non 200 status code in response
	ErrNon200Response = errors.New("Non 200 Response found")
)

func main() {
	ctx := context.Background()

	var (
		localDevMode = os.Getenv("LOCAL_DEVELOPMENT_MODE") == "true" || os.Getenv("LOCAL_DEVELOPMENT_MODE") == "1"

		baseURL                = os.Getenv("BASE_URL")
		oidcSignerKMSARN       = os.Getenv("KMS_OIDC_KEY_ARN")
		configBucketName       = os.Getenv("CONFIG_BUCKET_NAME")
		sessionTableName       = os.Getenv("SESSION_TABLE_NAME")
		googleOIDCClientIssuer = os.Getenv("GOOGLE_OIDC_ISSUER")
		googleOIDCClientID     = os.Getenv("GOOGLE_OIDC_CLIENT_ID")
		googleOIDCClientSecret = os.Getenv("GOOGLE_OIDC_CLIENT_SECRET")
	)

	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		log.Fatalf("creating aws sdk session: %v", err)
	}

	kmscli := kms.New(sess)
	s3cli := s3.New(sess)
	dynamocli := dynamodb.New(sess)

	var (
		jwtSigner crypto.Signer
		jwtKeyID  string
		clients   clientList
	)

	if googleOIDCClientIssuer == "" || googleOIDCClientID == "" || googleOIDCClientSecret == "" {
		log.Fatal("Google OIDC params not configured")
	}

	if localDevMode {
		// generate a crappy local key, for development purposes. Never erver
		// use this live.
		jwtSigner = localDevKey
		jwtKeyID = "localdev"

		clients = localDevelopmentClients

		// TODO - is there a more "efficient" way than coming back out to the
		// host? Does it matter?
		dynamocli = dynamodb.New(sess, &aws.Config{Endpoint: aws.String("http://host.docker.internal:8027")})
	} else {
		if oidcSignerKMSARN == "" {
			log.Fatal("KMS_OIDC_KEY_ARN must be set")
		}
		if configBucketName == "" {
			log.Fatal("CONFIG_BUCKET_NAME must be set")
		}

		// Use the KMS key
		s, err := awskms.NewSigner(ctx, kmscli, oidcSignerKMSARN)
		if err != nil {
			log.Fatalf("creating KMS signer: %v", err)
		}
		jwtSigner = s
		jwtKeyID = oidcSignerKMSARN

		cl, err := loadClients(ctx, s3cli, configBucketName)
		if err != nil {
			log.Fatalf("loading clients: %v", err)
		}
		clients = cl
	}

	// hash the key ID, to make it not easily reversable
	kh := sha256.New()
	if _, err := kh.Write([]byte(jwtKeyID)); err != nil {
		log.Fatal(err)
	}
	jwtKeyID = hex.EncodeToString(kh.Sum(nil))[0:16]

	jwts, err := signer.NewFromCrypto(jwtSigner, jwtKeyID)
	if err != nil {
		log.Fatalf("creating JWT signer from crypto.Signer: %v", err)
	}

	oidcmd := discovery.ProviderMetadata{
		Issuer:                baseURL,
		JWKSURI:               baseURL + "/keys",
		AuthorizationEndpoint: baseURL + "/auth",
		TokenEndpoint:         baseURL + "/token",
	}
	keysh := discovery.NewKeysHandler(jwts, 1*time.Hour)
	discoh, err := discovery.NewConfigurationHandler(&oidcmd, discovery.WithCoreDefaults())
	if err != nil {
		log.Fatalf("configuring metadata handler: %v", err)
	}

	st := &DynamoStore{
		client:           dynamocli,
		sessionTableName: sessionTableName,
	}

	oidcsvr, err := core.New(&core.Config{
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, st, clients, jwts)
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	oidccli, err := oidc.DiscoverClient(ctx,
		googleOIDCClientIssuer, googleOIDCClientID, googleOIDCClientSecret, baseURL+"/callback",
		oidc.WithAdditionalScopes([]string{"profile", "email"}),
	)
	if err != nil {
		log.Fatalf("oidc discovery on %s: %v", googleOIDCClientIssuer, err)
	}

	svr := server{
		issuer:          baseURL,
		oidcsvr:         oidcsvr,
		oidccli:         oidccli,
		storage:         st,
		tokenValidFor:   15 * time.Minute,
		refreshValidFor: 12 * time.Hour,
	}

	m := http.NewServeMux()

	m.Handle("/keys", keysh)
	m.Handle("/.well-known/openid-configuration", discoh)

	svr.AddHandlers(m)

	gateway.ListenAndServe("", m)
}

func mustDecodeKey(s string) *rsa.PrivateKey {
	var r *rsa.PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatalf("un-base64 key: %v", err)
	}
	buf := bytes.Buffer{}
	buf.Write(b)
	if err := gob.NewDecoder(&buf).Decode(&r); err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	return r
}

var localDevKey = mustDecodeKey("S/+BAwEBClByaXZhdGVLZXkB/4IAAQQBCVB1YmxpY0tleQH/hAABAUQB/4YAAQZQcmltZXMB/4gAAQtQcmVjb21wdXRlZAH/igAAACT/gwMBAQlQdWJsaWNLZXkB/4QAAQIBAU4B/4YAAQFFAQQAAAAK/4UFAQL/kAAAABn/hwIBAQpbXSpiaWcuSW50Af+IAAH/hgAASP+JAwEBEVByZWNvbXB1dGVkVmFsdWVzAf+KAAEEAQJEcAH/hgABAkRxAf+GAAEEUWludgH/hgABCUNSVFZhbHVlcwH/jgAAAB3/jQIBAQ5bXXJzYS5DUlRWYWx1ZQH/jgAB/4wAADH/iwMBAQhDUlRWYWx1ZQH/jAABAwEDRXhwAf+GAAEFQ29lZmYB/4YAAQFSAf+GAAAA/gFB/4IBAUEC6ucB8ZXiGQZmcUaBfbEOGfYZoPcs32XGIgHCugePcP3G7cIc5DxofX0gV5lo11+DLDFVYmVDTq+YNYrPcr6LHQH9AgACAAFBAkChrvc5tiwMhsNEEvzyal7aR9LyL3aIGivhMCLfUahUpBlsA0C4DkqqcOTzKZI1dDIibFOTgEncrRPzDWikCkEBAiEC+8WMHSJDcR+Mw/I/bsslFBjMZYkJ7j8ph8MrBmqtfp8hAu7Y7vKhGiT8Xek9Foifb7k/I/5NNOOFr4jUDCyVyejDAQEhAucjVxywBgZmlo6VaVLHwQSQN6XHh4xoBDKVJHzBlwG1ASEC0NeuV0i2a5CfLMnVYjDGp9ulxT4M+MRz79g5rOJsYbEBIQIR0UGs8sDAlPOVpuFq3dFa0PROE4YBEQuqe4Rdb+UwpgAA")
