package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"asteroid/internal/store/entity"
)

type ClientStore struct {
	client    *dynamodb.Client
	tableName string
}

func NewClientStore(client *dynamodb.Client, tableName string) *ClientStore {
	return &ClientStore{
		client:    client,
		tableName: tableName,
	}
}

func (s *ClientStore) GetClient(ctx context.Context, id string) (*entity.Client, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"id": &types.AttributeValueMemberS{Value: id},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, entity.ErrClientNotFound
	}

	var client entity.Client
	err = attributevalue.UnmarshalMap(result.Item, &client)
	if err != nil {
		return nil, err
	}

	return &client, nil
}

func (s *ClientStore) SaveClient(client *entity.Client) {
	// Note: This should return error in real implementation
	item, _ := attributevalue.MarshalMap(client)
	s.client.PutItem(context.TODO(), &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
}
