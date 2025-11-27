package signing

import (
	"fmt"
	"time"

	"asteroid/internal/crypto"
)

// Rotator coordinates key rotation operations using the Manager
// Responsibilities:
// - Orchestrate rotation flow (generate -> promote -> set expiration)
// - Handle ID token TTL alignment
// - Manage key lifecycle transitions
type Rotator struct {
	manager    *Manager
	idTokenTTL time.Duration
}

// NewRotator creates a new key rotator
func NewRotator(manager *Manager, idTokenTTL time.Duration) *Rotator {
	return &Rotator{
		manager:    manager,
		idTokenTTL: idTokenTTL,
	}
}

// RotateKey performs complete key rotation for the specified algorithm
// 1. Generate new key
// 2. Promote to active (demotes current active to valid-only)
// 3. Set expiration on old active key (ID token TTL)
func (r *Rotator) RotateKey(algorithm string) (*crypto.KeyPair, error) {
	// Step 1: Get current active key (if any) to set expiration
	var oldActiveKey *crypto.KeyPair
	if currentKey, err := r.manager.GetActiveKey(algorithm); err == nil {
		oldActiveKey = currentKey
	}

	// Step 2: Generate new key
	newKey, err := r.manager.GenerateKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Step 3: Promote new key to active (this demotes old key automatically)
	if err := r.manager.PromoteToActive(newKey.KeyID); err != nil {
		return nil, fmt.Errorf("failed to promote new key to active: %w", err)
	}

	// Step 4: Set expiration on old active key (ID token TTL alignment)
	if oldActiveKey != nil {
		expiresAt := time.Now().Add(r.idTokenTTL)
		if err := r.manager.SetKeyExpiration(oldActiveKey.KeyID, expiresAt); err != nil {
			// Log warning but don't fail rotation
			fmt.Printf("Warning: failed to set expiration on old key %s: %v\n", oldActiveKey.KeyID, err)
		}
	}

	return newKey, nil
}

// EnsureActiveKey ensures there is an active key for the algorithm
// If no active key exists, generates and activates one
func (r *Rotator) EnsureActiveKey(algorithm string) (*crypto.KeyPair, error) {
	// Check if active key already exists
	if key, err := r.manager.GetActiveKey(algorithm); err == nil {
		return key, nil
	}

	// No active key found, generate and activate one
	key, err := r.manager.GenerateKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial key: %w", err)
	}

	if err := r.manager.PromoteToActive(key.KeyID); err != nil {
		return nil, fmt.Errorf("failed to activate initial key: %w", err)
	}

	return key, nil
}

// CleanupExpiredKeys removes keys that have passed their expiration time
func (r *Rotator) CleanupExpiredKeys() []string {
	return r.manager.ExpireKeysByTime(time.Now())
}

// GetRotationStatus returns status information for rotation operations
func (r *Rotator) GetRotationStatus() RotationStatus {
	keys := r.manager.ListKeys()

	status := RotationStatus{
		TotalKeys:   len(keys),
		ActiveKeys:  make(map[string]KeyInfo),
		ValidKeys:   make(map[string]KeyInfo),
		ExpiredKeys: 0,
	}

	for _, key := range keys {
		if key.Status == KeyStatusActive {
			status.ActiveKeys[key.Algorithm] = key
		} else if key.Status == KeyStatusValid {
			status.ValidKeys[key.KeyID] = key
		} else if key.Status == KeyStatusExpired {
			status.ExpiredKeys++
		}
	}

	return status
}

// RotationStatus provides overview of key rotation state
type RotationStatus struct {
	TotalKeys   int                `json:"total_keys"`
	ActiveKeys  map[string]KeyInfo `json:"active_keys"` // algorithm -> key info
	ValidKeys   map[string]KeyInfo `json:"valid_keys"`  // keyID -> key info
	ExpiredKeys int                `json:"expired_keys"`
}
