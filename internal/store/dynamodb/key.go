package dynamodb

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"

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

	// Cache fields
	cachedKey *rsa.PrivateKey
	cachedKID string
	mutex     sync.RWMutex
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
	// Check cache with read lock
	s.mutex.RLock()
	if s.cachedKey != nil {
		defer s.mutex.RUnlock()
		return s.cachedKey, nil
	}
	s.mutex.RUnlock()

	// Acquire write lock for cache update
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Double-check in case another goroutine updated the cache
	if s.cachedKey != nil {
		return s.cachedKey, nil
	}

	record, err := s.fetchKeyRecord(ctx)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(record.PrivateKey))
	if err != nil {
		return nil, err
	}

	// Cache both key and KID
	s.cachedKey = key
	s.cachedKID = record.KID

	return key, nil
}

func (s *KeyStore) GetKid(ctx context.Context) (string, error) {
	// Check cache with read lock
	s.mutex.RLock()
	if s.cachedKID != "" {
		defer s.mutex.RUnlock()
		return s.cachedKID, nil
	}
	s.mutex.RUnlock()

	// Acquire write lock for cache update
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Double-check in case another goroutine updated the cache
	if s.cachedKID != "" {
		return s.cachedKID, nil
	}

	record, err := s.fetchKeyRecord(ctx)
	if err != nil {
		return "", err
	}

	// Cache KID (and key if not already cached)
	s.cachedKID = record.KID
	if s.cachedKey == nil {
		if key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(record.PrivateKey)); err == nil {
			s.cachedKey = key
		}
	}

	return record.KID, nil
}

func (s *KeyStore) fetchKeyRecord(ctx context.Context) (*keyRecord, error) {
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

	return &record, nil
}
