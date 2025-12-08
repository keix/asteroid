//go:build redis
// +build redis

package redis

import (
	"context"
	"testing"
	"time"

	"asteroid/internal/store/entity"
)

func TestAuthCodeStore_SaveAndGetAuthCode(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewAuthCodeStore(client)
	ctx := context.Background()

	// Test data
	authCode := &entity.AuthCode{
		Code:                "test-auth-code",
		ClientID:            "test-client",
		UserID:              "test-user",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		Scope:               "openid",
		State:               "test-state",
		Nonce:               "test-nonce",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	// Save auth code
	err := store.SaveAuthCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthCode failed: %v", err)
	}

	// Get auth code
	retrieved, err := store.GetAuthCode(ctx, "test-auth-code")
	if err != nil {
		t.Fatalf("GetAuthCode failed: %v", err)
	}

	// Verify
	if retrieved.Code != authCode.Code {
		t.Errorf("Expected code %s, got %s", authCode.Code, retrieved.Code)
	}
	if retrieved.ClientID != authCode.ClientID {
		t.Errorf("Expected client ID %s, got %s", authCode.ClientID, retrieved.ClientID)
	}
	if retrieved.UserID != authCode.UserID {
		t.Errorf("Expected user ID %s, got %s", authCode.UserID, retrieved.UserID)
	}
}

func TestAuthCodeStore_AuthCodeExpiration(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewAuthCodeStore(client)
	ctx := context.Background()

	// Expired auth code
	expiredCode := &entity.AuthCode{
		Code:                "expired-code",
		ClientID:            "test-client",
		UserID:              "test-user",
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid",
		State:               "test-state",
		Nonce:               "test-nonce",
		ExpiresAt:           time.Now().Add(-1 * time.Minute), // Expired
	}

	// Save expired code
	err := store.SaveAuthCode(ctx, expiredCode)
	if err != nil {
		t.Fatalf("SaveAuthCode failed: %v", err)
	}

	// Try to get expired code
	_, err = store.GetAuthCode(ctx, "expired-code")
	if err != entity.ErrAuthCodeNotFound {
		t.Errorf("Expected ErrAuthCodeNotFound, got %v", err)
	}
}

func TestAuthCodeStore_DeleteAuthCode(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewAuthCodeStore(client)
	ctx := context.Background()

	// Test data
	authCode := &entity.AuthCode{
		Code:        "delete-test-code",
		ClientID:    "test-client",
		UserID:      "test-user",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid",
		State:       "test-state",
		Nonce:       "test-nonce",
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Save and verify exists
	err := store.SaveAuthCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthCode failed: %v", err)
	}

	// Delete auth code
	err = store.DeleteAuthCode(ctx, "delete-test-code")
	if err != nil {
		t.Fatalf("DeleteAuthCode failed: %v", err)
	}

	// Verify not found
	_, err = store.GetAuthCode(ctx, "delete-test-code")
	if err != entity.ErrAuthCodeNotFound {
		t.Errorf("Expected ErrAuthCodeNotFound, got %v", err)
	}
}