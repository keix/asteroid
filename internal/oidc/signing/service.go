package signing

import (
	"context"
	"fmt"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/crypto"
	"asteroid/internal/crypto/persister"
)

// Service provides high-level signing key management
// Combines Manager and Rotator for complete key lifecycle
type Service struct {
	manager   *Manager
	rotator   *Rotator
	scheduler *Scheduler

	// Background cleanup
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// NewService creates a new signing service with background cleanup and rotation
func NewService(ctx context.Context, keyPersister crypto.KeyPersister, idTokenTTL time.Duration, rotationInterval time.Duration, clk clock.Clock) *Service {
	childCtx, cancel := context.WithCancel(ctx)

	manager := New(keyPersister)
	rotator := NewRotator(manager, idTokenTTL, clk)

	// RS256 is mandatory-to-implement for OpenID Providers. ES256 remains
	// available for JWT access tokens.
	algorithms := []string{"RS256", "ES256"}
	scheduler := NewScheduler(rotator, manager, rotationInterval, algorithms, clk)

	service := &Service{
		manager:   manager,
		rotator:   rotator,
		scheduler: scheduler,
		ctx:       childCtx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	// Skip loading existing keys to avoid key accumulation issues
	// if err := manager.LoadExistingKeys(); err != nil {
	//	fmt.Printf("Warning: failed to load existing keys: %v\n", err)
	// }

	// Always generate fresh keys on startup
	for _, algorithm := range algorithms {
		if _, err := rotator.EnsureActiveKey(algorithm); err != nil {
			fmt.Printf("Failed to generate initial key for %s: %v\n", algorithm, err)
			// Continue with other algorithms
		} else {
			fmt.Printf("Generated fresh key for algorithm: %s\n", algorithm)
		}
	}

	// Start background operations
	go service.cleanupLoop()
	scheduler.Start(childCtx)

	return service
}

// Close stops background operations
func (s *Service) Close() {
	s.scheduler.Stop()
	s.cancel()
	<-s.done
}

// RotateKey performs key rotation for the specified algorithm
func (s *Service) RotateKey(algorithm string) (*crypto.KeyPair, error) {
	return s.rotator.RotateKey(algorithm)
}

// GetActiveKey returns the active signing key for the algorithm
func (s *Service) GetActiveKey(algorithm string) (*crypto.KeyPair, error) {
	return s.manager.GetActiveKey(algorithm)
}

// GetKeyByID returns a key by ID for verification
func (s *Service) GetKeyByID(keyID string) (*crypto.KeyPair, error) {
	return s.manager.GetKeyByID(keyID)
}

// GetJWKSKeys returns all valid keys for JWKS endpoint
func (s *Service) GetJWKSKeys() []*crypto.KeyPair {
	return s.manager.GetJWKSKeys()
}

// EnsureActiveKey ensures there is an active key for the algorithm
func (s *Service) EnsureActiveKey(algorithm string) (*crypto.KeyPair, error) {
	return s.rotator.EnsureActiveKey(algorithm)
}

// GetSigner returns the signer for the specified algorithm
func (s *Service) GetSigner(algorithm string) (crypto.Signer, error) {
	return s.manager.GetSigner(algorithm)
}

// GetRotationStatus returns current rotation status
func (s *Service) GetRotationStatus() RotationStatus {
	return s.rotator.GetRotationStatus()
}

// ListKeys returns all keys with their status
func (s *Service) ListKeys() []KeyInfo {
	return s.manager.ListKeys()
}

// cleanupLoop runs background key cleanup
func (s *Service) cleanupLoop() {
	defer close(s.done)

	ticker := time.NewTicker(1 * time.Minute) // Cleanup every minute
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			expiredKeys := s.rotator.CleanupExpiredKeys()
			if len(expiredKeys) > 0 {
				fmt.Printf("Cleaned up %d expired keys: %v\n", len(expiredKeys), expiredKeys)
			}
		}
	}
}

// NewFileService creates a signing service with file persistence (development)
func NewFileService(ctx context.Context, keyDir string, idTokenTTL time.Duration, rotationInterval time.Duration, clk clock.Clock) *Service {
	filePersister := persister.New(keyDir)
	return NewService(ctx, filePersister, idTokenTTL, rotationInterval, clk)
}

// Example for production KMS integration:
// func NewKMSService(ctx context.Context, kmsConfig KMSConfig, idTokenTTL time.Duration) *Service {
//     kmsPersister := persister.NewKMS(kmsConfig)
//     return NewService(ctx, kmsPersister, idTokenTTL)
// }
