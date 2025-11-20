package memory

import (
	"context"
	"sync"
	"time"

	"asteroid/internal/store/entity"
)

type AuthCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*entity.AuthCode
}

func NewAuthCodeStore() *AuthCodeStore {
	store := &AuthCodeStore{
		codes: make(map[string]*entity.AuthCode),
	}

	go store.cleanup()
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

	if time.Now().After(authCode.ExpiresAt) {
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

func (s *AuthCodeStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for code, authCode := range s.codes {
			if now.After(authCode.ExpiresAt) {
				delete(s.codes, code)
			}
		}
		s.mu.Unlock()
	}
}