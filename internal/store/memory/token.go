package memory

import (
	"context"
	"sync"
	"time"

	"asteroid/internal/store/entity"
)

type TokenStore struct {
	accessTokens  map[string]*entity.AccessToken
	refreshTokens map[string]*entity.RefreshToken
	mu            sync.RWMutex
}

func NewTokenStore() *TokenStore {
	ts := &TokenStore{
		accessTokens:  make(map[string]*entity.AccessToken),
		refreshTokens: make(map[string]*entity.RefreshToken),
	}

	// Start cleanup goroutine for expired tokens
	go ts.cleanupExpiredTokens()

	return ts
}

func (ts *TokenStore) SaveAccessToken(ctx context.Context, token *entity.AccessToken) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.accessTokens[token.Token] = token
	return nil
}

func (ts *TokenStore) SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.refreshTokens[token.Token] = token
	return nil
}

func (ts *TokenStore) GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	refreshToken, exists := ts.refreshTokens[token]
	if !exists {
		return nil, entity.ErrRefreshTokenNotFound
	}

	// Check if expired
	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, entity.ErrRefreshTokenExpired
	}

	return refreshToken, nil
}

func (ts *TokenStore) DeleteRefreshToken(ctx context.Context, token string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.refreshTokens, token)
	return nil
}

// cleanupExpiredTokens periodically removes expired tokens
func (ts *TokenStore) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		ts.mu.Lock()

		// Clean access tokens
		for token, accessToken := range ts.accessTokens {
			if now.After(accessToken.ExpiresAt) {
				delete(ts.accessTokens, token)
			}
		}

		// Clean refresh tokens
		for token, refreshToken := range ts.refreshTokens {
			if now.After(refreshToken.ExpiresAt) {
				delete(ts.refreshTokens, token)
			}
		}

		ts.mu.Unlock()
	}
}
