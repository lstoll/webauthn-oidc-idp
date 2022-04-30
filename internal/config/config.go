package config

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/jszwec/s3fs"
	"gopkg.in/yaml.v2"
)

// Config is our classic god configuration struct. It contains all the
// configured information for running the app. In addition it acts as a file
// store abstraction for the various underlying stores the Config may be loaded
// from. This allows it to act as a central cache and pre-load items as needed,
// e.g for lambda usage.
//
// this should not be passed around as-is - in general favour adding accessors
// for the data that is needed and consuming those as thin interfaces, or have
// the various items configurable directly from this.
type Config struct {
	Issuer        string         `yaml:"issuer"`
	OIDCSigner    OIDCSigner     `yaml:"oidcSigner"`
	Policies      Policies       `yaml:"policies"`
	Providers     []Provider     `yaml:"providers"`
	ClientSources []ClientSource `yaml:"clientSources"`
	Storage       Storage        `yaml:"storage"`
	AWS           AWS            `yaml:"aws"`

	// internal details
	fs.FS
	configFlags configFlags
	awsConfig   client.ConfigProvider
}

func (c *Config) LoadFromS3(ctx context.Context, s3client s3iface.S3API, url *url.URL, awsConfig client.ConfigProvider) error {
	bucket := url.Host
	cfgPath := url.Path
	cfgPrefix := filepath.Dir(cfgPath)

	resp, err := s3client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &cfgPath,
	})
	if err != nil {
		return fmt.Errorf("getting config from bucket %s key %s: %v", bucket, cfgPath, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading bucket %s key %s: %v", bucket, cfgPath, err)
	}

	cs := os.ExpandEnv(string(b))

	cfg := &Config{}

	if err := yaml.Unmarshal([]byte(cs), cfg); err != nil {
		return fmt.Errorf("unmarshaling expanded config from %s: %v", url.String(), err)
	}

	c.overrideFromFlags()

	c.awsConfig = awsConfig

	cfg.FS = s3fs.New(s3client, url.Host)
	if cfgPrefix != "" && cfgPrefix != "/" {
		f, err := fs.Sub(cfg.FS, strings.TrimPrefix(cfgPrefix, "/"))
		if err != nil {
			return fmt.Errorf("subfs %s: %v", cfgPrefix, err)
		}
		cfg.FS = f
	}

	return nil
}

func (c *Config) Flags(fs *flag.FlagSet) {
	flag.StringVar(&c.configFlags.kmsOIDCArn, "oidc-jwt-kms-arn", os.Getenv("KMS_OIDC_KEY_ARN"), "ARN to the KMS key to use for signing")
	flag.StringVar(&c.configFlags.sessionTableName, "dynamo-session-table-name", os.Getenv("SESSION_TABLE_NAME"), "Name of the DynamoDB table to track sessions in")
	flag.StringVar(&c.configFlags.webauthnUserTableName, "dynamo-webauthn-user-table-name", os.Getenv("WEBAUTHN_USER_TABLE_NAME"), "Name of the DynamoDB table to track sessions in")

}

func (c *Config) overrideFromFlags() {
	if c.configFlags.kmsOIDCArn != "" {
		c.OIDCSigner.Type = "kms"
		c.OIDCSigner.KMSSigner.ARN = c.configFlags.kmsOIDCArn
	}
	if c.configFlags.sessionTableName != "" {
		c.Storage.Type = "dynamodb"
		c.Storage.DynamoDB.SessionTableName = c.configFlags.sessionTableName
	}
	if c.configFlags.webauthnUserTableName != "" {
		c.Storage.Type = "dynamodb"
		c.Storage.DynamoDB.WebauthnUserTableName = c.configFlags.webauthnUserTableName
	}
}

func (c *Config) AWSConfig() (client.ConfigProvider, error) {
	return c.awsConfig, nil
}

func (c *Config) Validate() error {
	var errs []string

	ve := func(format string, a ...interface{}) {
		errs = append(errs, fmt.Sprintf(format, a...))
	}

	if c.Issuer == "" {
		ve("issuer is required")
	}

	if len(c.Providers) < 1 {
		ve("must have at least one provider")
	}
	var webauthnProviderCount int
	for _, p := range c.Providers {
		switch p.Type {
		case "oidc":
		case "webauthn":
			webauthnProviderCount++
			if p.Webauthn.ClientID == "" || p.Webauthn.ClientSecret == "" {
				ve("client id and secret must be provided for webauthn provider")
			}
		default:
			ve("provider %s must be one of webauthn, oidc", p.ID)
		}
	}
	if webauthnProviderCount > 1 {
		ve("no more than one webauthn provider can be specified")
	}

	if len(c.ClientSources) != 1 {
		ve("must be exactly one client source")
	}
	if c.ClientSources[0].Type != "file" {
		ve("client source must be type file")
	}

	switch c.Storage.Type {
	case "dynamodb":
		if c.Storage.DynamoDB.SessionTableName == "" || c.Storage.DynamoDB.WebauthnUserTableName == "" {
			ve("all dynamo table names must be specified")
		}
	default:
		ve("unknown storage type %s", c.Storage.Type)
	}

	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, ", "))
	}
	return nil
}

func (c *Config) HasUpstreamClaimsPolicy() bool {
	return c.Policies.UpstreamClaims != nil
}

func (c *Config) UpstreamClaimsPolicy() (string, error) {
	if !c.HasUpstreamClaimsPolicy() {
		return "", fmt.Errorf("no upstream claims policy specified")
	}
	f, err := c.FS.Open(*c.Policies.UpstreamClaims)
	if err != nil {
		return "", fmt.Errorf("opening %s: %v", *c.Policies.UpstreamClaims, err)
	}
	r, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("reading %s: %v", *c.Policies.UpstreamClaims, err)
	}
	return string(r), nil
}

type OIDCSigner struct {
	Type         string       `yaml:"type"`
	KMSSigner    KMSSigner    `yaml:"kms"`
	StaticSigner StaticSigner `yaml:"static"`
}

type KMSSigner struct {
	ARN string `yaml:"arn"`
}

type StaticSigner struct {
	KeyID  string `yaml:"keyID"`
	KeyPEM string `yaml:"keyPEM"`
}

type Provider struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
	Name string `yaml:"name"`
	// ACR value this provider satisfies, optional
	ACR string `yaml:"acr"`
	// AMR value for this provider, optional
	AMR  string `yaml:"amr"`
	OIDC *struct {
		Issuer       string `yaml:"issuer"`
		ClientID     string `yaml:"clientID"`
		ClientSecret string `yaml:"clientSecret"`
	} `yaml:"oidc"`
	Webauthn *struct {
		// ClientID is a client ID for the webauthn manager to authenticate
		// with.
		//
		// TODO - these are transitional, ideally we'd self-allocation these
		ClientID     string `yaml:"clientID"`
		ClientSecret string `yaml:"clientSecret"`
		// AdminSubjects is a list of subjects allowed to administer the
		// service
		AdminSubjects []string `yaml:"adminSubjects"`
	} `yaml:"webauthn"`
}

type Policies struct {
	UpstreamClaims *string `yaml:"upstreamClaims"`
}

type ClientSource struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
	File *struct {
		Filename string `yaml:"filename"`
	}
}

type Storage struct {
	Type     string `yaml:"type"`
	DynamoDB struct {
		SessionTableName      string `yaml:"sessionTableName"`
		WebauthnUserTableName string `yaml:"webauthnUserTableName"`
	}
}

type AWS struct {
	S3Endpoint       string `yaml:"s3Endpoint"`
	S3ForcePathStyle bool   `yaml:"s3ForcePathStyle"`
	DynamoEndpoint   string `yaml:"dynamoEndpoint"`
}

type configFlags struct {
	sessionTableName      string
	webauthnUserTableName string
	kmsOIDCArn            string
}
