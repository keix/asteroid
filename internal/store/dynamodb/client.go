package dynamodb

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"asteroid/internal/store/entity"
)

type ClientStore struct {
	client    *dynamodb.Client
	tableName string

	// Cache
	cache map[string]*entity.Client
	mutex sync.RWMutex
}

func NewClientStore(client *dynamodb.Client, tableName string) *ClientStore {
	return &ClientStore{
		client:    client,
		tableName: tableName,
		cache:     make(map[string]*entity.Client),
	}
}

func (s *ClientStore) GetClient(ctx context.Context, id string) (*entity.Client, error) {
	// Check cache first
	s.mutex.RLock()
	if client, exists := s.cache[id]; exists {
		s.mutex.RUnlock()
		return client, nil
	}
	s.mutex.RUnlock()

	// Fetch from DynamoDB
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

	// Cache the result
	s.mutex.Lock()
	s.cache[id] = &client
	s.mutex.Unlock()

	return &client, nil
}

func (s *ClientStore) SaveClient(ctx context.Context, client *entity.Client) error {
	item, err := attributevalue.MarshalMap(client)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item:      item,
	})
	if err != nil {
		return err
	}

	// Update cache
	s.mutex.Lock()
	s.cache[client.ID] = client
	s.mutex.Unlock()

	return nil
}
