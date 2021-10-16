package main

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

func TestDynamoWebauthn(t *testing.T) {
	ctx := context.Background()

	ddburl := os.Getenv("TEST_DYNAMODB_URL")
	if ddburl == "" {
		t.Skip("TEST_DYNAMODB_URL")
	}
	awsCfg := aws.NewConfig()
	// each user ID gets it's own DB space, so create a new one per test run.
	// this'll leave junk in the local instance, but w/e
	awsCfg.Credentials = credentials.NewStaticCredentials(fmt.Sprintf("TEST-%d", time.Now().Unix()), "SECRET", "")
	awsCfg.Region = aws.String("in-my-computer")
	awsCfg.Endpoint = &ddburl
	dc := dynamodb.New(session.New(awsCfg))
	if _, err := dc.CreateTableWithContext(ctx, &dynamodb.CreateTableInput{
		BillingMode: aws.String(dynamodb.BillingModePayPerRequest),
		TableName:   aws.String("webauthnusers"),
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String(dynamodb.ScalarAttributeTypeS),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String(dynamodb.KeyTypeHash),
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	ds := &DynamoStore{
		client:                dc,
		webauthnUserTableName: "webauthnusers",
	}

	u := &DynamoWebauthnUser{
		Email: "abc@def.com",
	}
	id, err := ds.PutUser(ctx, u)
	if err != nil {
		t.Fatalf("putting user: %v", err)
	}
	u.ID = id

	gu, ok, err := ds.GetUserByEmail(ctx, "abc@def.com")
	if err != nil {
		t.Fatalf("getting user: %v", err)
	}
	if !ok {
		t.Error("user was not found")
	}

	if !reflect.DeepEqual(gu, u) {
		t.Errorf("want user: %#v\ngot user: %#v", gu, u)
	}

	u2 := &DynamoWebauthnUser{
		Email: u.Email,
	}

	if _, err := ds.PutUser(ctx, u2); err == nil {
		t.Error("no error inserting duplicate user")
	}

	_, ok, err = ds.GetUserByEmail(ctx, "unknown@domain.com")
	if err != nil {
		t.Fatalf("getting unknown user: %v", err)
	}
	if ok {
		t.Error("unknown user should not be ok")
	}

	u.Email = "new@def.com"
	id, err = ds.PutUser(ctx, u)
	if err != nil {
		t.Fatalf("putting user: %v", err)
	}
	if id != u.ID {
		t.Errorf("update changed user ID")
	}

	us, err := ds.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 {
		t.Errorf("want 1 user, got %d", len(us))
	}
}
