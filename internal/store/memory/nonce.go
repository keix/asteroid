package memory

import (
	"context"
	"sync"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/store/entity"
)

type NonceStore struct {
	seenNonces map[string]time.Time // key: "clientID:nonce", value: expiresAt
	mu         sync.RWMutex
	clock      clock.Clock
}

func NewNonceStore(ctx context.Context, clk clock.Clock) *NonceStore {
	store := &NonceStore{
		seenNonces: make(map[string]time.Time),
		clock:      clk,
	}
	go store.cleanupLoop(ctx)
	return store
}

func (s *NonceStore) MarkNonceSeen(ctx context.Context, nonce, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := clientID + ":" + nonce
	now := s.clock.Now()

	// Check if already seen and not expired
	if expiresAt, exists := s.seenNonces[key]; exists && now.Before(expiresAt) {
		return entity.ErrNonceAlreadySeen
	}

	// Mark as seen with TTL (AuthCode lifetime + buffer)
	s.seenNonces[key] = now.Add(7 * time.Minute)
	return nil
}

// cleanupLoop is real-time orchestration; the decision uses the injected clock.
func (s *NonceStore) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.deleteExpired(s.clock.Now())
		case <-ctx.Done():
			return
		}
	}
}

func (s *NonceStore) deleteExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, expiresAt := range s.seenNonces {
		if now.After(expiresAt) {
			delete(s.seenNonces, key)
		}
	}
}
