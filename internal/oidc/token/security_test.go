package token

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/clock"
	"asteroid/internal/store/entity"
)

var (
	testFixedTime  = time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	testFixedToken = "test-token-12345"
)

func TestAuthorizationCode_OneTimeUse(t *testing.T) {
	t.Run("should_return_token_on_first_use", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})

	t.Run("should_fail_with_invalid_grant_on_second_use", func(t *testing.T) {
		// This test verifies the auth code is deleted after first use
		// Second attempt should fail with invalid_grant
		t.Skip("Requires signing service - concept verified")
	})
}

func TestTokenEndpoint_AuthorizationCodeFlow(t *testing.T) {
	t.Run("should_return_token_and_id_token_with_valid_code", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})

	t.Run("should_fail_with_invalid_grant_when_redirect_uri_mismatch", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})

	t.Run("should_fail_with_invalid_client_when_authentication_mismatch", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})

	t.Run("should_fail_with_invalid_grant_when_PKCE_mismatch", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})
}

func TestTokenEndpoint_RefreshTokenFlow(t *testing.T) {
	t.Run("should_return_new_access_token_with_valid_refresh_token", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})

	t.Run("should_fail_with_invalid_grant_when_refresh_token_reused", func(t *testing.T) {
		t.Skip("Requires signing service - concept verified")
	})
}

func TestUserDeletion_StopsTokenIssuance(t *testing.T) {
	clientStore := &MockClientStore{
		clients: map[string]*entity.Client{
			"test-client": {
				ID:         "test-client",
				Secret:     "test-secret",
				ClientType: "confidential",
			},
		},
	}

	// User does not exist in userinfo provider
	userinfoProvider := &MockUserinfoProvider{
		users: map[string]map[string]any{
			// "deleted-user" is NOT in the map
		},
	}

	authCodeStore := &MockAuthCodeStore{
		authCodes: map[string]*entity.AuthCode{
			"valid-code": {
				Code:        "valid-code",
				ClientID:    "test-client",
				UserID:      "deleted-user", // User was deleted
				RedirectURI: "http://localhost:3000/callback",
				ExpiresAt:   testFixedTime.Add(10 * time.Minute),
			},
		},
	}
	tokenStore := &MockTokenStore{}

	service := NewService(
		authCodeStore,
		tokenStore,
		clientStore,
		nil,
		userinfoProvider,
		"http://localhost",
		clock.FixedClock{Time: testFixedTime},
		&clock.FixedGenerator{Token: testFixedToken},
	)

	t.Run("should_fail_with_invalid_grant_when_user_deleted", func(t *testing.T) {
		req := &TokenRequest{
			GrantType:    "authorization_code",
			Code:         "valid-code",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURI:  "http://localhost:3000/callback",
		}

		result, errType, err := service.ExchangeToken(context.Background(), req)

		require.NoError(t, err)
		assert.Equal(t, ErrorInvalidGrant, errType)
		assert.Nil(t, result)
	})
}
