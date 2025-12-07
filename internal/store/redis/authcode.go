//go:build redis
// +build redis

package redis

import (
	"context"
	"encoding/json"
	"time"

	"asteroid/internal/store/entity"
	"github.com/redis/go-redis/v9"
)

type AuthCodeStore struct {
	client *redis.Client
	prefix string
}

func NewAuthCodeStore(client *redis.Client) *AuthCodeStore {
	return &AuthCodeStore{
		client: client,
		prefix: "authcode:",
	}
}

func (s *AuthCodeStore) SaveAuthCode(ctx context.Context, code *entity.AuthCode) error {
	data, err := json.Marshal(code)
	if err != nil {
		return err
	}

	key := s.prefix + code.Code
	ttl := time.Until(code.ExpiresAt)

	return s.client.Set(ctx, key, data, ttl).Err()
}

func (s *AuthCodeStore) GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error) {
	key := s.prefix + code

	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, entity.ErrAuthCodeNotFound
		}
		return nil, err
	}

	var authCode entity.AuthCode
	err = json.Unmarshal([]byte(data), &authCode)
	if err != nil {
		return nil, err
	}

	// Double check expiration (Redis TTL should handle this, but just in case)
	if time.Now().After(authCode.ExpiresAt) {
		return nil, entity.ErrAuthCodeNotFound
	}

	return &authCode, nil
}

func (s *AuthCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	key := s.prefix + code
	return s.client.Del(ctx, key).Err()
}
