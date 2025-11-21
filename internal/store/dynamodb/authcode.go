package dynamodb

import (
	"context"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"asteroid/internal/store/entity"
)

type AuthCodeStore struct {
	client    *dynamodb.Client
	tableName string
}

func NewAuthCodeStore(client *dynamodb.Client, tableName string) *AuthCodeStore {
	return &AuthCodeStore{
		client:    client,
		tableName: tableName,
	}
}

func (s *AuthCodeStore) SaveAuthCode(ctx context.Context, code *entity.AuthCode) error {
	item, err := attributevalue.MarshalMap(code)
	if err != nil {
		return err
	}

	// Set TTL for automatic cleanup
	ttl := code.ExpiresAt.Unix()
	item["ttl"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
	return err
}

func (s *AuthCodeStore) GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"code": &types.AttributeValueMemberS{Value: code},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, entity.ErrAuthCodeNotFound
	}

	var authCode entity.AuthCode
	err = attributevalue.UnmarshalMap(result.Item, &authCode)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(authCode.ExpiresAt) {
		return nil, entity.ErrAuthCodeNotFound
	}

	return &authCode, nil
}

func (s *AuthCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"code": &types.AttributeValueMemberS{Value: code},
		},
	})
	return err
}
