package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/jszwec/s3fs"
	"github.com/lstoll/awskms"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/signer"
	"gopkg.in/yaml.v2"
)

// config is our classic god configuration struct. It contains all the
// configured information for running the app. In addition it acts as a file
// store abstraction for the various underlying stores the config may be loaded
// from. This allows it to act as a central cache and pre-load items as needed,
// e.g for lambda usage.
//
// this should not be passed around as-is - in general favour adding accessors
// for the data that is needed and consuming those as thin interfaces, or have
// the various items configurable directly from this.
type config struct {
	Issuer     string `yaml:"issuer"`
	OIDCSigner struct {
		Type      string `yaml:"type"`
		KMSSigner struct {
			ARN string `yaml:"arn"`
		} `yaml:"kms"`
		StaticSigner *struct {
			KeyID  string `yaml:"keyID"`
			KeyPEM string `yaml:"keyPEM"`
		} `yaml:"static"`
	} `yaml:"oidcSigner"`
	Policies *struct {
		UpstreamClaims *string `yaml:"upstreamClaims"`
	} `yaml:"policies"`
	Providers []struct {
		ID   string `yaml:"id"`
		Type string `yaml:"type"`
		OIDC *struct {
			Issuer       string `yaml:"issuer"`
			ClientID     string `yaml:"clientID"`
			ClientSecret string `yaml:"clientSecret"`
		}
	} `yaml:"providers"`
	ClientSources []struct {
		ID   string `yaml:"id"`
		Type string `yaml:"type"`
		File *struct {
			Filename string `yaml:"filename"`
		}
	} `yaml:"clientSources"`
	Storage struct {
		Type     string `yaml:"type"`
		DynamoDB struct {
			SessionTableName string `yaml:"sessionTableName"`
		}
	} `yaml:"storage"`
	AWS struct {
		S3Endpoint       string `yaml:"s3Endpoint"`
		S3ForcePathStyle bool   `yaml:"s3ForcePathStyle"`
		DynamoEndpoint   string `yaml:"dynamoEndpoint"`
	} `yaml:"aws"`

	// internal details
	fs        fs.FS
	awsConfig client.ConfigProvider
}

func newConfigFromS3(ctx context.Context, s3client s3iface.S3API, url *url.URL, awsConfig client.ConfigProvider) (*config, error) {
	bucket := url.Host
	cfgPath := url.Path
	cfgPrefix := filepath.Dir(cfgPath)

	resp, err := s3client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &cfgPath,
	})
	if err != nil {
		return nil, fmt.Errorf("getting config from bucket %s key %s: %v", bucket, cfgPath, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading bucket %s key %s: %v", bucket, cfgPath, err)
	}

	cs := os.ExpandEnv(string(b))

	cfg := &config{}

	if err := yaml.Unmarshal([]byte(cs), cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling expanded config from %s: %v", url.String(), err)
	}

	cfg.fs = s3fs.New(s3client, url.Host)
	if cfgPrefix != "" && cfgPrefix != "/" {
		f, err := fs.Sub(cfg.fs, strings.TrimPrefix(cfgPrefix, "/"))
		if err != nil {
			return nil, fmt.Errorf("subfs %s: %v", cfgPrefix, err)
		}
		cfg.fs = f
	}

	cfg.awsConfig = awsConfig

	return cfg, nil
}

func (c *config) OverrideFromFlags(f flags) {
	if f.kmsOIDCArn != "" {
		c.OIDCSigner.Type = "kms"
		c.OIDCSigner.KMSSigner.ARN = f.kmsOIDCArn
	}
	if f.sessionTableName != "" {
		c.Storage.Type = "dynamodb"
		c.Storage.DynamoDB.SessionTableName = f.sessionTableName
	}
}

func (c *config) Validate() error {
	var errs []string

	ve := func(msg string) {
		errs = append(errs, msg)
	}

	if c.Issuer == "" {
		ve("issuer is required")
	}

	if len(c.Providers) != 1 {
		ve("must be exactly one provider")
	}
	if c.Providers[0].Type != "oidc" {
		ve("provider must be type oidc")
	}

	if len(c.ClientSources) != 1 {
		ve("must be exactly one client source")
	}
	if c.ClientSources[0].Type != "file" {
		ve("client source must be type file")
	}

	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, ", "))
	}
	return nil
}

func (c *config) HasUpstreamClaimsPolicy() bool {
	return c.Policies.UpstreamClaims != nil
}

func (c *config) UpstreamClaimsPolicy() (string, error) {
	if !c.HasUpstreamClaimsPolicy() {
		return "", fmt.Errorf("no upstream claims policy specified")
	}
	f, err := c.fs.Open(*c.Policies.UpstreamClaims)
	if err != nil {
		return "", fmt.Errorf("opening %s: %v", *c.Policies.UpstreamClaims, err)
	}
	r, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading %s: %v", *c.Policies.UpstreamClaims, err)
	}
	return string(r), nil
}

func (c *config) OIDCJWTSigner(ctx context.Context) (core.Signer, discovery.KeySource, error) {
	switch c.OIDCSigner.Type {
	case "static":
		privPem, _ := pem.Decode([]byte(c.OIDCSigner.StaticSigner.KeyPEM))
		if privPem.Type != "RSA PRIVATE KEY" {
			return nil, nil, fmt.Errorf("key should be RSA PRIVATE KEY, but got: %s", privPem.Type)
		}

		parsed, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing private key: %v", err)
		}

		jwts, err := signer.NewFromCrypto(parsed, c.OIDCSigner.StaticSigner.KeyID)
		if err != nil {
			log.Fatalf("creating JWT signer from crypto.Signer: %v", err)
		}

		return jwts, jwts, nil
	case "kms":
		kmscli := kms.New(c.awsConfig)

		s, err := awskms.NewSigner(ctx, kmscli, c.OIDCSigner.KMSSigner.ARN)
		if err != nil {
			return nil, nil, fmt.Errorf("creating KMS signer: %v", err)
		}

		// hash the key ID so we aren't leaking the ARN
		kh := sha256.New()
		if _, err := kh.Write([]byte(c.OIDCSigner.KMSSigner.ARN)); err != nil {
			log.Fatal(err)
		}
		jwtKeyID := hex.EncodeToString(kh.Sum(nil))[0:16]

		jwts, err := signer.NewFromCrypto(s, jwtKeyID)
		if err != nil {
			log.Fatalf("creating JWT signer from crypto.Signer: %v", err)
		}

		return jwts, jwts, nil
	default:
		return nil, nil, fmt.Errorf("invalid signer type %s", c.OIDCSigner.Type)
	}
}

func (c *config) Clients() (core.ClientSource, error) {
	return &fsClients{
		readerFn: func() (io.ReadCloser, error) {
			return c.fs.Open(c.ClientSources[0].File.Filename)
		},
	}, nil
}

func (c *config) GetStorage() (Storage, error) {
	awsCfg := aws.NewConfig()
	if c.AWS.DynamoEndpoint != "" {
		awsCfg.Endpoint = &c.AWS.DynamoEndpoint
	}
	dc := dynamodb.New(c.awsConfig, awsCfg)

	return &DynamoStore{
		client:           dc,
		sessionTableName: c.Storage.DynamoDB.SessionTableName,
	}, nil
}
