package main

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/lstoll/idp/internal/config"
	"github.com/pardot/oidc/core"
)

type Storage interface {
	core.SessionManager
	WebauthnUserStore
	GetMetadata(ctx context.Context, sessionID string) (Metadata, bool, error)
	PutMetadata(ctx context.Context, sessionID string, meta Metadata) error
	Authenticate(ctx context.Context, sessionID string, auth Authentication) error
	GetAuthentication(ctx context.Context, sessionID string) (Authentication, bool, error)
}

func newStorageFromConfig(cfg *config.Config) (Storage, error) {
	mcfg, err := cfg.AWSConfig()
	if err != nil {
		return nil, err
	}
	awsCfg := aws.NewConfig()
	if cfg.AWS.DynamoEndpoint != "" {
		awsCfg.Endpoint = &cfg.AWS.DynamoEndpoint
	}
	dc := dynamodb.New(mcfg, awsCfg)

	return &DynamoStore{
		client:                dc,
		sessionTableName:      cfg.Storage.DynamoDB.SessionTableName,
		webauthnUserTableName: cfg.Storage.DynamoDB.WebauthnUserTableName,
	}, nil
}
