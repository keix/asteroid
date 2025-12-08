//go:build redis
// +build redis

package redis

import (
	"context"
	"testing"

	"asteroid/internal/store/entity"
)

func TestNonceStore_MarkNonceSeen(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewNonceStore(client)
	ctx := context.Background()

	// First attempt should succeed
	err := store.MarkNonceSeen(ctx, "test-nonce", "test-client")
	if err != nil {
		t.Fatalf("MarkNonceSeen failed: %v", err)
	}

	// Second attempt should fail (replay attack)
	err = store.MarkNonceSeen(ctx, "test-nonce", "test-client")
	if err != entity.ErrNonceAlreadySeen {
		t.Errorf("Expected ErrNonceAlreadySeen, got %v", err)
	}
}

func TestNonceStore_DifferentClientsCanUseSameNonce(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewNonceStore(client)
	ctx := context.Background()

	// Same nonce for different clients should both succeed
	err := store.MarkNonceSeen(ctx, "shared-nonce", "client1")
	if err != nil {
		t.Fatalf("MarkNonceSeen failed for client1: %v", err)
	}

	err = store.MarkNonceSeen(ctx, "shared-nonce", "client2")
	if err != nil {
		t.Fatalf("MarkNonceSeen failed for client2: %v", err)
	}
}

func TestNonceStore_EmptyNonce(t *testing.T) {
	client, cleanup := setupTestRedis()
	defer cleanup()

	store := NewNonceStore(client)
	ctx := context.Background()

	// Empty nonce should be handled
	err := store.MarkNonceSeen(ctx, "", "test-client")
	if err != nil {
		t.Fatalf("MarkNonceSeen failed for empty nonce: %v", err)
	}

	// Second attempt with empty nonce should fail
	err = store.MarkNonceSeen(ctx, "", "test-client")
	if err != entity.ErrNonceAlreadySeen {
		t.Errorf("Expected ErrNonceAlreadySeen for empty nonce replay, got %v", err)
	}
}