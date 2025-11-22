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

func NewTokenStore(ctx context.Context) *TokenStore {
	ts := &TokenStore{
		accessTokens:  make(map[string]*entity.AccessToken),
		refreshTokens: make(map[string]*entity.RefreshToken),
	}

	// Start cleanup goroutine for expired tokens
	go ts.cleanupExpiredTokens(ctx)

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
func (ts *TokenStore) cleanupExpiredTokens(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ts.deleteExpired()
		case <-ctx.Done():
			return
		}
	}
}

func (ts *TokenStore) deleteExpired() {
	now := time.Now()
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for token, accessToken := range ts.accessTokens {
		if now.After(accessToken.ExpiresAt) {
			delete(ts.accessTokens, token)
		}
	}

	for token, refreshToken := range ts.refreshTokens {
		if now.After(refreshToken.ExpiresAt) {
			delete(ts.refreshTokens, token)
		}
	}
}
