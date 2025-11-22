package memory

import (
	"context"
	"sync"
	"time"

	"asteroid/internal/store/entity"
)

type NonceStore struct {
	seenNonces map[string]time.Time // key: "clientID:nonce", value: expiresAt
	mu         sync.RWMutex
}

func NewNonceStore(ctx context.Context) *NonceStore {
	store := &NonceStore{
		seenNonces: make(map[string]time.Time),
	}
	go store.cleanup(ctx)
	return store
}

func (s *NonceStore) MarkNonceSeen(ctx context.Context, nonce, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := clientID + ":" + nonce
	now := time.Now()

	// Check if already seen and not expired
	if expiresAt, exists := s.seenNonces[key]; exists && now.Before(expiresAt) {
		return entity.ErrNonceAlreadySeen
	}

	// Mark as seen with TTL (AuthCode lifetime + buffer)
	s.seenNonces[key] = now.Add(7 * time.Minute)
	return nil
}

func (s *NonceStore) cleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for key, expiresAt := range s.seenNonces {
				if now.After(expiresAt) {
					delete(s.seenNonces, key)
				}
			}
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}
