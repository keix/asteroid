//go:build redis
// +build redis

package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"asteroid/internal/store/entity"
)

type NonceStore struct {
	client *redis.Client
}

func NewNonceStore(client *redis.Client) *NonceStore {
	return &NonceStore{
		client: client,
	}
}

func (s *NonceStore) MarkNonceSeen(ctx context.Context, nonce, clientID string) error {
	key := fmt.Sprintf("nonce:%s:%s", clientID, nonce)

	// SETNX with TTL (atomic operation)
	// TTL = AuthCode lifetime + buffer for token exchange
	result := s.client.SetNX(ctx, key, "seen", 7*time.Minute)
	if result.Err() != nil {
		return result.Err()
	}

	if !result.Val() {
		return entity.ErrNonceAlreadySeen // Key already exists = replay attack
	}

	return nil // Success: nonce marked as seen for first time
}
