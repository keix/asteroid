package memory

import (
	"context"
	"sync"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/store/entity"
)

type AuthCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*entity.AuthCode
	clock clock.Clock
}

func NewAuthCodeStore(ctx context.Context, clk clock.Clock) *AuthCodeStore {
	store := &AuthCodeStore{
		codes: make(map[string]*entity.AuthCode),
		clock: clk,
	}

	go store.cleanupLoop(ctx)
	return store
}

func (s *AuthCodeStore) SaveAuthCode(ctx context.Context, code *entity.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes[code.Code] = code
	return nil
}

func (s *AuthCodeStore) GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, exists := s.codes[code]
	if !exists {
		return nil, entity.ErrAuthCodeNotFound
	}

	if s.clock.Now().After(authCode.ExpiresAt) {
		return nil, entity.ErrAuthCodeNotFound
	}

	return authCode, nil
}

func (s *AuthCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.codes, code)
	return nil
}

// cleanupLoop is real-time orchestration; the decision uses the injected clock.
func (s *AuthCodeStore) cleanupLoop(ctx context.Context) {
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

func (s *AuthCodeStore) deleteExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for code, authCode := range s.codes {
		if now.After(authCode.ExpiresAt) {
			delete(s.codes, code)
		}
	}
}
