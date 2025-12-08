package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/store/entity"
)

func TestAuthorizeEndpoint_PublicClient_PKCE(t *testing.T) {
	clientStore := &MockClientStore{
		clients: map[string]*entity.Client{
			"mobile-app": {
				ID:           "mobile-app",
				ClientType:   "public",
				RedirectURIs: []string{"com.example.app://callback"},
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

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	t.Run("should_fail_when_PKCE_required_but_missing_code_challenge", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "mobile-app",
			RedirectURI:  "com.example.app://callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			UserID:       "user-123",
			// PKCE parameters missing
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorInvalidRequest, errType)
		assert.Nil(t, result)
	})

	t.Run("should_fail_with_invalid_redirect_uri", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:            "mobile-app",
			RedirectURI:         "https://evil.com/callback", // Invalid
			ResponseType:        "code",
			Scope:               "openid",
			State:               "test-state",
			UserID:              "user-123",
			CodeChallenge:       "test-challenge",
			CodeChallengeMethod: "S256",
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorInvalidRedirectURI, errType)
		assert.Nil(t, result)
	})

	t.Run("should_succeed_with_valid_request_and_return_code_and_state", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:            "mobile-app",
			RedirectURI:         "com.example.app://callback",
			ResponseType:        "code",
			Scope:               "openid",
			State:               "test-state",
			UserID:              "user-123",
			CodeChallenge:       "test-challenge",
			CodeChallengeMethod: "S256",
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorNone, errType)
		assert.NotNil(t, result)
		assert.Contains(t, result.RedirectURL, "code=")
		assert.Contains(t, result.RedirectURL, "state=test-state")
	})
}

func TestAuthorizeEndpoint_ConfidentialClient(t *testing.T) {
	clientStore := &MockClientStore{
		clients: map[string]*entity.Client{
			"web-app": {
				ID:           "web-app",
				Secret:       "secret",
				ClientType:   "confidential",
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

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	t.Run("should_succeed_without_PKCE_for_confidential_client", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "web-app",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			UserID:       "user-123",
			// No PKCE parameters - should be OK for confidential client
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorNone, errType)
		assert.NotNil(t, result)
		assert.Contains(t, result.RedirectURL, "code=")
	})

	t.Run("should_fail_without_authentication_header", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "web-app",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			// UserID empty - no authentication
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorAccessDenied, errType)
		assert.Nil(t, result)
	})

	t.Run("should_fail_with_client_id_mismatch", func(t *testing.T) {
		req := &AuthorizeRequest{
			ClientID:     "invalid-client",
			RedirectURI:  "https://example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "test-state",
			UserID:       "user-123",
		}

		result, errType, err := service.Authorize(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorInvalidClient, errType)
		assert.Nil(t, result)
	})
}
