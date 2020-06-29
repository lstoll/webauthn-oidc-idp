package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/google/uuid"
	"github.com/pardot/oidc/core"
)

// `dynamodbav:"myName,omitempty"`

type Metadata struct {
	Subject  string
	Userinfo map[string]interface{}
}

type Session struct {
	SessionID string `dynamodbav:"session_id"`
	// Meta      *Metadata `dynamodbav:"metadata,omitempty"`
	// CoreSession interface{} `dynamodbav:"core_session,omitempty"` // See how dynamo handles this, otherwise revert to bytes of json
}

var _ core.SessionManager = (*DynamoStore)(nil)

// DynamoStore implements both the session manager interface, and other storage items we need
type DynamoStore struct {
	client dynamodbiface.DynamoDBAPI

	sessionTableName string
}

/* Session manager */

func (d *DynamoStore) GetSession(ctx context.Context, sessionID string, into core.Session) (bool, error) {
	result, err := d.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: &d.sessionTableName,
		Key: map[string]*dynamodb.AttributeValue{
			"session_id": {
				S: &sessionID,
			},
		},
	})
	if err != nil {
		return false, fmt.Errorf("getting session %s: %v", sessionID, err)
	}

	var sess Session
	err = dynamodbattribute.UnmarshalMap(result.Item, &sess)
	if err != nil {
		return false, fmt.Errorf("unmarshaling session %s: %v", sessionID, err)
	}
	if sess.SessionID == "" {
		return false, nil
	}

	// re-unmarshal the core session again
	if err := dynamodbattribute.UnmarshalMap(result.Item["core_session"].M, &into); err != nil {
		return false, fmt.Errorf("Failed to unmarshal the core session")
	}

	return true, nil
}

func (d *DynamoStore) PutSession(ctx context.Context, sess core.Session) error {
	if sess.ID() == "" {
		return fmt.Errorf("session has no ID")
	}

	av, err := dynamodbattribute.MarshalMap(sess)
	if err != nil {
		return fmt.Errorf("marshaling session for dynamo: %v", err)
	}

	_, err = d.client.UpdateItemWithContext(ctx, &dynamodb.UpdateItemInput{
		TableName: &d.sessionTableName,
		Key: map[string]*dynamodb.AttributeValue{
			"session_id": {
				S: aws.String(sess.ID()),
			},
		},
		UpdateExpression: aws.String("set core_session = :c, expires_at = :e"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":c": {
				M: av,
			},
			":e": {
				N: aws.String(fmt.Sprintf("%d", sess.Expiry().Unix())),
			},
		},
		ReturnValues: aws.String("UPDATED_NEW"),
	})
	if err != nil {
		return fmt.Errorf("putting session %s: %v", sess.ID(), err)
	}

	return nil
}

func (d *DynamoStore) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := d.client.DeleteItemWithContext(ctx, &dynamodb.DeleteItemInput{
		TableName: &d.sessionTableName,
		Key: map[string]*dynamodb.AttributeValue{
			"session_id": {
				S: &sessionID,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("deleting %s: %v", sessionID, err)
	}
	return nil
}

func (d *DynamoStore) NewID() string {
	return uuid.New().String()
}

/* End session manager */

func (d *DynamoStore) GetMetadata(ctx context.Context, sessionID string) (Metadata, bool, error) {
	result, err := d.client.GetItemWithContext(ctx, &dynamodb.GetItemInput{
		TableName: &d.sessionTableName,
		Key: map[string]*dynamodb.AttributeValue{
			"session_id": {
				S: &sessionID,
			},
		},
	})
	if err != nil {
		return Metadata{}, false, fmt.Errorf("getting metadata from session %s: %v", sessionID, err)
	}

	var sess Session
	err = dynamodbattribute.UnmarshalMap(result.Item, &sess)
	if err != nil {
		return Metadata{}, false, fmt.Errorf("unmarshaling session %s: %v", sessionID, err)
	}

	if sess.SessionID == "" {
		return Metadata{}, false, nil
	}

	var meta Metadata
	err = dynamodbattribute.UnmarshalMap(result.Item["metadata"].M, &meta)
	if err != nil {
		return Metadata{}, false, fmt.Errorf("unmarshaling session %s: %v", sessionID, err)
	}

	if sess.SessionID == "" {
		return Metadata{}, false, nil
	}

	return meta, true, nil
}

func (d *DynamoStore) PutMetadata(ctx context.Context, sessionID string, meta Metadata) error {
	av, err := dynamodbattribute.MarshalMap(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata for dynamo: %v", err)
	}

	_, err = d.client.UpdateItemWithContext(ctx, &dynamodb.UpdateItemInput{
		TableName: &d.sessionTableName,
		Key: map[string]*dynamodb.AttributeValue{
			"session_id": {
				S: &sessionID,
			},
		},
		UpdateExpression: aws.String("set metadata = :m"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":m": {
				M: av,
			},
		},
		ReturnValues: aws.String("UPDATED_NEW"),
	})
	if err != nil {
		return fmt.Errorf("putting metadata in session %s: %v", sessionID, err)
	}

	return nil
}
