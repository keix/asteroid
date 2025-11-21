package dynamodb

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/golang-jwt/jwt/v5"
)

type KeyStore struct {
	client    *dynamodb.Client
	tableName string
	keyID     string
}

type keyRecord struct {
	KeyID      string `dynamodbav:"key_id"`
	PrivateKey string `dynamodbav:"private_key_pem"`
	KID        string `dynamodbav:"kid"`
}

func NewKeyStore(client *dynamodb.Client, tableName, keyID string) *KeyStore {
	return &KeyStore{
		client:    client,
		tableName: tableName,
		keyID:     keyID,
	}
}

func (s *KeyStore) GetSigningKey(ctx context.Context) (*rsa.PrivateKey, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"key_id": &types.AttributeValueMemberS{Value: s.keyID},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, errors.New("key not found")
	}

	var record keyRecord
	err = attributevalue.UnmarshalMap(result.Item, &record)
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM([]byte(record.PrivateKey))
}

func (s *KeyStore) GetKid(ctx context.Context) (string, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"key_id": &types.AttributeValueMemberS{Value: s.keyID},
		},
		ProjectionExpression: aws.String("kid"),
	})
	if err != nil {
		return "", err
	}

	if result.Item == nil {
		return "", errors.New("key not found")
	}

	var record keyRecord
	err = attributevalue.UnmarshalMap(result.Item, &record)
	if err != nil {
		return "", err
	}

	return record.KID, nil
}
