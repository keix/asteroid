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

type TokenStore struct {
	client            *dynamodb.Client
	accessTokenTable  string
	refreshTokenTable string
}

func NewTokenStore(client *dynamodb.Client, accessTokenTable, refreshTokenTable string) *TokenStore {
	return &TokenStore{
		client:            client,
		accessTokenTable:  accessTokenTable,
		refreshTokenTable: refreshTokenTable,
	}
}

func (ts *TokenStore) SaveAccessToken(ctx context.Context, token *entity.AccessToken) error {
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return err
	}

	// Add TTL for automatic deletion
	item["ttl"] = &types.AttributeValueMemberN{
		Value: strconv.FormatInt(token.ExpiresAt.Unix(), 10),
	}

	_, err = ts.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(ts.accessTokenTable),
		Item:      item,
	})
	return err
}

func (ts *TokenStore) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	item, err := attributevalue.MarshalMap(token)
	if err != nil {
		return err
	}

	// Add TTL for automatic deletion
	item["ttl"] = &types.AttributeValueMemberN{
		Value: strconv.FormatInt(token.ExpiresAt.Unix(), 10),
	}

	_, err = ts.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(ts.refreshTokenTable),
		Item:      item,
	})
	return err
}

func (ts *TokenStore) GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	result, err := ts.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(ts.refreshTokenTable),
		Key: map[string]types.AttributeValue{
			"token": &types.AttributeValueMemberS{Value: token},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, entity.ErrRefreshTokenNotFound
	}

	var refreshToken entity.RefreshToken
	if err := attributevalue.UnmarshalMap(result.Item, &refreshToken); err != nil {
		return nil, err
	}

	now := time.Now()
	if now.After(refreshToken.ExpiresAt) {
		return nil, entity.ErrRefreshTokenExpired
	}

	return &refreshToken, nil
}

func (ts *TokenStore) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := ts.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(ts.refreshTokenTable),
		Key: map[string]types.AttributeValue{
			"token": &types.AttributeValueMemberS{Value: token},
		},
	})
	return err
}
