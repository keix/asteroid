package signing

import (
	"fmt"
	"sync"
	"time"

	"asteroid/internal/crypto"
)

// Manager is a pure key state machine for signing key lifecycle
// Responsibilities:
// - Active/Valid/Expired key state management
// - Key retrieval by algorithm and ID
// - Key promotion and demotion
// - JWKS key listing
// - Uses crypto.KeyPersister interface for persistence
type Manager struct {
	mu       sync.RWMutex
	registry *crypto.Registry

	// Pure state storage
	activeKeys       map[string]*crypto.KeyPair // algorithm -> active signing key
	verificationKeys map[string]*crypto.KeyPair // keyID -> key for verification (includes active)

	// Persistence (using crypto.KeyPersister interface)
	persister crypto.KeyPersister
}

// KeyStatus represents the lifecycle state of a signing key
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"  // Used for signing new tokens + verification
	KeyStatusValid   KeyStatus = "valid"   // Used for verification only (old tokens)
	KeyStatusExpired KeyStatus = "expired" // Removed from JWKS
)

// KeyInfo represents key metadata for listing operations
type KeyInfo struct {
	KeyID     string     `json:"key_id"`
	Algorithm string     `json:"algorithm"`
	Status    KeyStatus  `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// New creates a new signing key manager
func New(persister crypto.KeyPersister) *Manager {
	return &Manager{
		registry:         crypto.NewRegistry(),
		activeKeys:       make(map[string]*crypto.KeyPair),
		verificationKeys: make(map[string]*crypto.KeyPair),
		persister:        persister,
	}
}

// LoadExistingKeys loads keys from persistence (startup operation)
func (m *Manager) LoadExistingKeys() error {
	keys, err := m.persister.LoadKeys()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load all persisted keys into valid set
	for _, key := range keys {
		m.verificationKeys[key.KeyID] = key

		// If no active key for this algorithm, use this one
		if _, exists := m.activeKeys[key.Algorithm]; !exists {
			m.activeKeys[key.Algorithm] = key
		}
	}

	return nil
}

// GenerateKey creates a new key pair and persists it
func (m *Manager) GenerateKey(algorithm string) (*crypto.KeyPair, error) {
	generator, exists := m.registry.GetGenerator(algorithm)
	if !exists {
		return nil, ErrUnsupportedAlgorithm
	}

	// Generate and persist using crypto interface
	kp, err := generator.GenerateAndPersist(m.persister)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to verification keys (not active by default)
	m.verificationKeys[kp.KeyID] = kp

	return kp, nil
}

// PromoteToActive makes a key the active signing key for its algorithm
func (m *Manager) PromoteToActive(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.verificationKeys[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	// Clear expiration when promoted to active (fresh active key)
	key.ExpiresAt = nil

	// Set as active for this algorithm
	m.activeKeys[key.Algorithm] = key

	return nil
}

// DemoteFromActive demotes the active key for an algorithm (becomes valid-only)
func (m *Manager) DemoteFromActive(algorithm string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from active set (remains in valid set for verification)
	delete(m.activeKeys, algorithm)

	return nil
}

// ExpireKey marks a key as expired and removes it from all sets
func (m *Manager) ExpireKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if key exists
	_, exists := m.verificationKeys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	delete(m.verificationKeys, keyID)

	// Remove from active if it was active
	for alg, activeKey := range m.activeKeys {
		if activeKey.KeyID == keyID {
			delete(m.activeKeys, alg)
			break
		}
	}

	return nil
}

// ExpireKeysByTime removes keys that have passed their expiration time
func (m *Manager) ExpireKeysByTime(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiredKeys []string

	for keyID, key := range m.verificationKeys {
		if key.ExpiresAt != nil && now.After(*key.ExpiresAt) {
			delete(m.verificationKeys, keyID)
			expiredKeys = append(expiredKeys, keyID)

			// Remove from active if it was active
			for alg, activeKey := range m.activeKeys {
				if activeKey.KeyID == keyID {
					delete(m.activeKeys, alg)
					break
				}
			}
		}
	}

	return expiredKeys
}

// GetActiveKey returns the active signing key for the algorithm
func (m *Manager) GetActiveKey(algorithm string) (*crypto.KeyPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.activeKeys[algorithm]
	if !exists {
		return nil, ErrNoActiveKey
	}

	return key, nil
}

// GetKeyByID returns a key by its ID (for verification)
func (m *Manager) GetKeyByID(keyID string) (*crypto.KeyPair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.verificationKeys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return key, nil
}

// GetJWKSKeys returns all valid keys for JWKS endpoint
func (m *Manager) GetJWKSKeys() []*crypto.KeyPair {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []*crypto.KeyPair
	for _, key := range m.verificationKeys {
		keys = append(keys, key)
	}

	return keys
}

// ListKeys returns all keys with their status information
func (m *Manager) ListKeys() []KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []KeyInfo

	for keyID, key := range m.verificationKeys {
		status := KeyStatusValid

		// Check if it's active
		for _, activeKey := range m.activeKeys {
			if activeKey.KeyID == keyID {
				status = KeyStatusActive
				break
			}
		}

		result = append(result, KeyInfo{
			KeyID:     keyID,
			Algorithm: key.Algorithm,
			Status:    status,
			CreatedAt: key.CreatedAt,
			ExpiresAt: key.ExpiresAt,
		})
	}

	return result
}

// EnsureActiveKey ensures there is an active key for the algorithm
func (m *Manager) EnsureActiveKey(algorithm string) error {
	m.mu.RLock()
	_, exists := m.activeKeys[algorithm]
	m.mu.RUnlock()

	if !exists {
		kp, err := m.GenerateKey(algorithm)
		if err != nil {
			return err
		}
		return m.PromoteToActive(kp.KeyID)
	}

	return nil
}

// HasActiveKey checks if there is an active key for the algorithm
func (m *Manager) HasActiveKey(algorithm string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.activeKeys[algorithm]
	return exists
}

// SetKeyExpiration sets an expiration time on a key
func (m *Manager) SetKeyExpiration(keyID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.verificationKeys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	key.ExpiresAt = &expiresAt

	return nil
}

// GetSigner returns the signer for the specified algorithm
func (m *Manager) GetSigner(algorithm string) (crypto.Signer, error) {
	signer, exists := m.registry.GetSigner(algorithm)
	if !exists {
		return nil, ErrUnsupportedAlgorithm
	}

	return signer, nil
}
