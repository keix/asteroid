//go:build dynamodb
// +build dynamodb

package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"asteroid/internal/store/entity"
)

type NonceStore struct {
	client    *dynamodb.Client
	tableName string
}

type SeenNonce struct {
	ClientNonce string `dynamodbav:"client_nonce"` // PK: "clientID#nonce"
	SeenAt      int64  `dynamodbav:"seen_at"`
	TTL         int64  `dynamodbav:"ttl"` // DynamoDB TTL attribute
}

func NewNonceStore(client *dynamodb.Client, tableName string) *NonceStore {
	return &NonceStore{
		client:    client,
		tableName: tableName,
	}
}

func (s *NonceStore) MarkNonceSeen(ctx context.Context, nonce, clientID string) error {
	key := clientID + "#" + nonce
	now := time.Now()

	item := SeenNonce{
		ClientNonce: key,
		SeenAt:      now.Unix(),
		TTL:         now.Add(7 * time.Minute).Unix(), // TTL = AuthCode lifetime + buffer
	}

	marshaledItem, err := attributevalue.MarshalMap(item)
	if err != nil {
		return err
	}

	// Conditional put: only insert if key doesn't exist
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.tableName),
		Item:                marshaledItem,
		ConditionExpression: aws.String("attribute_not_exists(client_nonce)"),
	})

	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return entity.ErrNonceAlreadySeen // Item already exists = replay attack
		}
		return err
	}

	return nil // Success: nonce marked as seen for first time
}
