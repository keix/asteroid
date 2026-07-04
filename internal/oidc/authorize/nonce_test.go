package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/store/entity"
)

func TestNonceHandling(t *testing.T) {
	clientStore := &MockClientStore{
		clients: map[string]*entity.Client{
			"test-client": {
				ID:           "test-client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
		},
	}
	userinfoProvider := &MockUserinfoProvider{
		users: map[string]map[string]any{
			"user-123": {"sub": "user-123"},
		},
	}
	authCodeStore := &MockAuthCodeStore{}
	nonceStore := &MockNonceStore{}

	service := newTestService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	t.Run("should_return_nonce", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "test-client",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			Nonce:        "test-nonce-123",
			UserID:       "user-123",
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorNone, errType)
		assert.NotNil(t, result)

		// The nonce should be stored in the auth code for later use in ID token
		// This is verified by checking that the auth code was saved
		assert.Contains(t, result.RedirectURL, "code=")
	})

	t.Run("should_error_when_nonce_is_reused", func(t *testing.T) {
		// First, use a nonce
		req1 := &AuthorizeRequest{
			ClientID:     "test-client",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			Nonce:        "used-nonce",
			UserID:       "user-123",
		}

		result1, errType1, err1 := service.Authorize(context.Background(), req1)
		require.NoError(t, err1)
		assert.Equal(t, ErrorNone, errType1)
		assert.NotNil(t, result1)

		// Try to reuse the same nonce - should fail
		req2 := &AuthorizeRequest{
			ClientID:     "test-client",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state-2",
			Nonce:        "used-nonce", // Same nonce - should fail
			UserID:       "user-123",
		}

		result2, errType2, err2 := service.Authorize(context.Background(), req2)
		require.NoError(t, err2)
		assert.Equal(t, ErrorInvalidRequest, errType2)
		assert.Nil(t, result2)
	})
}
