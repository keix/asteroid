//go:build redis
// +build redis

package redis

import (
	"context"
	"testing"
	"time"

	"asteroid/internal/store/entity"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestRedis() (*redis.Client, func()) {
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	cleanup := func() {
		client.Close()
		mr.Close()
	}

	return client, cleanup
}

func TestTokenStore_SaveAndGetRefreshToken(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewTokenStore(client)
	ctx := context.Background()

	// Test data
	refreshToken := &entity.RefreshToken{
		Token:     "test-refresh-token",
		ClientID:  "test-client",
		UserID:    "test-user",
		Scope:     "openid",
		AuthTime:  time.Now().Add(-5 * time.Minute).Truncate(time.Second),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Save refresh token
	err := store.SaveRefreshToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	// Get refresh token
	retrieved, err := store.GetRefreshToken(ctx, "test-refresh-token")
	if err != nil {
		t.Fatalf("GetRefreshToken failed: %v", err)
	}

	// Verify
	if retrieved.Token != refreshToken.Token {
		t.Errorf("Expected token %s, got %s", refreshToken.Token, retrieved.Token)
	}
	if retrieved.ClientID != refreshToken.ClientID {
		t.Errorf("Expected client ID %s, got %s", refreshToken.ClientID, retrieved.ClientID)
	}
	if retrieved.UserID != refreshToken.UserID {
		t.Errorf("Expected user ID %s, got %s", refreshToken.UserID, retrieved.UserID)
	}
	if !retrieved.AuthTime.Equal(refreshToken.AuthTime) {
		t.Errorf("Expected auth time %s, got %s", refreshToken.AuthTime, retrieved.AuthTime)
	}
}

func TestTokenStore_RefreshTokenExpiration(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewTokenStore(client)
	ctx := context.Background()

	// Expired refresh token
	expiredToken := &entity.RefreshToken{
		Token:     "expired-token",
		ClientID:  "test-client",
		UserID:    "test-user",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	// Save expired token
	err := store.SaveRefreshToken(ctx, expiredToken)
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	// Try to get expired token
	_, err = store.GetRefreshToken(ctx, "expired-token")
	if err != entity.ErrRefreshTokenExpired {
		t.Errorf("Expected ErrRefreshTokenExpired, got %v", err)
	}
}

func TestTokenStore_DeleteRefreshToken(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewTokenStore(client)
	ctx := context.Background()

	// Test data
	refreshToken := &entity.RefreshToken{
		Token:     "delete-test-token",
		ClientID:  "test-client",
		UserID:    "test-user",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Save and verify exists
	err := store.SaveRefreshToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	// Delete token
	err = store.DeleteRefreshToken(ctx, "delete-test-token")
	if err != nil {
		t.Fatalf("DeleteRefreshToken failed: %v", err)
	}

	// Verify not found
	_, err = store.GetRefreshToken(ctx, "delete-test-token")
	if err != entity.ErrRefreshTokenNotFound {
		t.Errorf("Expected ErrRefreshTokenNotFound, got %v", err)
	}
}

func TestTokenStore_SaveAccessToken(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewTokenStore(client)
	ctx := context.Background()

	// Test data
	accessToken := &entity.AccessToken{
		Token:     "test-access-token",
		ClientID:  "test-client",
		UserID:    "test-user",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	// Save access token (write-only operation)
	err := store.SaveAccessToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}

	// Verify token was stored in Redis
	exists := client.Exists(ctx, "access_token:test-access-token").Val()
	if exists != 1 {
		t.Error("Access token was not stored in Redis")
	}
}
