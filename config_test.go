package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	configTestBucket = "config-test"
)

func TestS3Config(t *testing.T) {
	murl := os.Getenv("MINIO_URL")
	if murl == "" {
		t.Skip("MINIO_URL not set")
	}
	ctx := context.Background()

	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewEnvCredentials(),
	})
	if err != nil {
		t.Fatalf("creating aws sdk session: %v", err)
	}
	s3cli := s3.New(sess, &aws.Config{Endpoint: &murl, S3ForcePathStyle: aws.Bool(true)})

	if err := s3cli.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(configTestBucket),
	}, func(page *s3.ListObjectsV2Output, _ bool) bool {
		for _, o := range page.Contents {
			if _, err := s3cli.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(configTestBucket),
				Key:    o.Key,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return true
	}); err != nil {
		if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != s3.ErrCodeNoSuchBucket {
			// actual error
			t.Fatal(err)
		}
	}

	if _, err := s3cli.DeleteBucketWithContext(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(configTestBucket),
	}); err != nil {
		if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != s3.ErrCodeNoSuchBucket {
			// actual error
			t.Fatal(err)
		}
	}
	if _, err := s3cli.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(configTestBucket),
	}); err != nil {
		t.Fatal(err)
	}

	bucketContents := map[string]string{
		"config/config.yaml": `
oidcSigner:
  type: ephemeral
policies:
  upstreamClaims: upstreamClaims.rego
`,
		"config/upstreamClaims.rego": `
package upstream

default allow = false

allow = true {
	input.iss == "https://accounts.google.com"
	input.email == "lincoln.stoll@gmail.com"
}`,
	}
	for k, v := range bucketContents {
		if _, err := s3cli.PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket: aws.String(configTestBucket),
			Key:    &k,
			Body:   bytes.NewReader([]byte(v)),
		}); err != nil {
			t.Fatal(err)
		}
	}

	cu, err := url.Parse("s3://" + configTestBucket + "/config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := newConfigFromS3(ctx, s3cli, cu, sess)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.OIDCSigner.Type != "ephemeral" {
		t.Error("signer type should be ephemeral")
	}

	if !cfg.HasUpstreamClaimsPolicy() {
		t.Error("should have upstream policy")
	}

	p, err := cfg.UpstreamClaimsPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p != bucketContents["config/upstreamClaims.rego"] {
		t.Errorf("wrong contents returned")
	}
}
