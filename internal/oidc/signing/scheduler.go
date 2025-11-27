package signing

import (
	"context"
	"fmt"
	"time"

	"asteroid/internal/crypto"
)

// Scheduler handles automatic key rotation based on time policies
type Scheduler struct {
	rotator          *Rotator
	manager          *Manager
	rotationInterval time.Duration
	algorithms       []string

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// NewScheduler creates a new rotation scheduler
func NewScheduler(rotator *Rotator, manager *Manager, rotationInterval time.Duration, algorithms []string) *Scheduler {
	return &Scheduler{
		rotator:          rotator,
		manager:          manager,
		rotationInterval: rotationInterval,
		algorithms:       algorithms,
	}
}

// Start begins automatic rotation scheduling
func (s *Scheduler) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})

	// Undercover cryptography: the most important changes are silent.
	go s.rotationLoop()
}

// Stop halts automatic rotation
func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}

// rotationLoop runs automatic rotation checks
func (s *Scheduler) rotationLoop() {
	defer close(s.done)

	ticker := time.NewTicker(1 * time.Minute) // Check every minute (testing)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkAndRotateKeys()
		}
	}
}

// checkAndRotateKeys checks if keys need rotation and performs it
func (s *Scheduler) checkAndRotateKeys() {
	now := time.Now()

	for _, algorithm := range s.algorithms {
		activeKey, err := s.manager.GetActiveKey(algorithm)
		if err != nil {
			// No active key, ensure one exists
			if _, ensureErr := s.rotator.EnsureActiveKey(algorithm); ensureErr != nil {
				fmt.Printf("Failed to ensure active key for %s: %v\n", algorithm, ensureErr)
			}
			continue
		}

		// Check if key needs rotation
		if s.shouldRotateKey(activeKey, now) {
			newKey, err := s.rotator.RotateKey(algorithm)
			if err != nil {
				fmt.Printf("Failed to rotate key for %s: %v\n", algorithm, err)
			} else {
				fmt.Printf("Rotated key for %s: %s -> %s\n", algorithm, activeKey.KeyID, newKey.KeyID)
			}
		}
	}
}

// shouldRotateKey determines if a key should be rotated
func (s *Scheduler) shouldRotateKey(key *crypto.KeyPair, now time.Time) bool {
	keyAge := now.Sub(key.CreatedAt)
	return keyAge >= s.rotationInterval
}
