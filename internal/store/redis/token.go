package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"asteroid/internal/store/entity"
)

type TokenStore struct {
	client *redis.Client
}

func NewTokenStore(client *redis.Client) *TokenStore {
	return &TokenStore{
		client: client,
	}
}

func (ts *TokenStore) SaveAccessToken(ctx context.Context, token *entity.AccessToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	return ts.client.Set(ctx, "access_token:"+token.Token, data, ttl).Err()
}

func (ts *TokenStore) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	return ts.client.Set(ctx, "refresh_token:"+token.Token, data, ttl).Err()
}

func (ts *TokenStore) GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	data, err := ts.client.Get(ctx, "refresh_token:"+token).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, entity.ErrRefreshTokenNotFound
		}
		return nil, err
	}

	var refreshToken entity.RefreshToken
	if err := json.Unmarshal([]byte(data), &refreshToken); err != nil {
		return nil, err
	}

	now := time.Now()
	if now.After(refreshToken.ExpiresAt) {
		return nil, entity.ErrRefreshTokenExpired
	}

	return &refreshToken, nil
}

func (ts *TokenStore) DeleteRefreshToken(ctx context.Context, token string) error {
	return ts.client.Del(ctx, "refresh_token:"+token).Err()
}
