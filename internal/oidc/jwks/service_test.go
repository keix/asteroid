package jwks

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/clock"
	"asteroid/internal/crypto/persister"
	"asteroid/internal/oidc/signing"
)

func TestJWKSEndpoint(t *testing.T) {
	// Create temporary key persister
	tempDir := t.TempDir()
	keyPersister := persister.New(tempDir)

	// Create signing service with key rotation
	signingService := signing.NewService(context.Background(), keyPersister, 15*time.Minute, 1*time.Hour, clock.RealClock{})
	defer signingService.Close()

	// Create JWKS service
	service := NewService(signingService)

	t.Run("should_include_kid_for_each_key", func(t *testing.T) {
		jwks, err := service.GetJWKSet(context.Background())
		require.NoError(t, err)

		// At least one key should exist (ES256 default)
		require.NotEmpty(t, jwks.Keys)

		// Each key should have a kid
		for _, key := range jwks.Keys {
			assert.NotEmpty(t, key.Kid)
		}
	})

	t.Run("should_have_correct_algorithm", func(t *testing.T) {
		jwks, err := service.GetJWKSet(context.Background())
		require.NoError(t, err)

		// Find ES256 key (default)
		var es256Key *JWK
		for i := range jwks.Keys {
			if jwks.Keys[i].Alg == "ES256" {
				es256Key = &jwks.Keys[i]
				break
			}
		}

		require.NotNil(t, es256Key, "ES256 key should exist")
		assert.Equal(t, "ES256", es256Key.Alg)
		assert.Equal(t, "sig", es256Key.Use)
		assert.Equal(t, "EC", es256Key.Kty)
	})

	t.Run("should_have_valid_JWK_format", func(t *testing.T) {
		jwks, err := service.GetJWKSet(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, jwks.Keys)

		key := jwks.Keys[0]

		// Required fields for JWK
		assert.NotEmpty(t, key.Kty) // Key type
		assert.NotEmpty(t, key.Use) // Public key use
		assert.NotEmpty(t, key.Kid) // Key ID
		assert.NotEmpty(t, key.Alg) // Algorithm

		// For EC keys
		if key.Kty == "EC" {
			assert.NotEmpty(t, key.Crv) // Curve
			assert.NotEmpty(t, key.X)   // X coordinate
			assert.NotEmpty(t, key.Y)   // Y coordinate
		}

		// For RSA keys
		if key.Kty == "RSA" {
			assert.NotEmpty(t, key.N) // Modulus
			assert.NotEmpty(t, key.E) // Exponent
		}
	})

	t.Run("should_return_only_current_keys_during_rotation", func(t *testing.T) {
		// This test verifies that only current keys are returned
		// Key rotation is handled by the signing service
		jwks, err := service.GetJWKSet(context.Background())
		require.NoError(t, err)
		require.NotEmpty(t, jwks.Keys)

		// Should have exactly one key (current key)
		assert.Len(t, jwks.Keys, 1)
		assert.NotEmpty(t, jwks.Keys[0].Kid)
	})
}
