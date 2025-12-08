package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/store/entity"
	"asteroid/internal/userinfo"
)

// Mock stores for testing
type MockClientStore struct {
	clients map[string]*entity.Client
}

func (m *MockClientStore) GetClient(ctx context.Context, id string) (*entity.Client, error) {
	if m.clients == nil {
		return nil, entity.ErrClientNotFound
	}
	client, exists := m.clients[id]
	if !exists {
		return nil, entity.ErrClientNotFound
	}
	return client, nil
}

type MockUserinfoProvider struct {
	users map[string]map[string]any
}

func (m *MockUserinfoProvider) Fetch(ctx context.Context, sub string) (map[string]any, error) {
	if m.users == nil {
		return nil, userinfo.ErrUserNotFound
	}
	user, exists := m.users[sub]
	if !exists {
		return nil, userinfo.ErrUserNotFound
	}
	return user, nil
}

type MockAuthCodeStore struct {
	authCodes map[string]*entity.AuthCode
}

func (m *MockAuthCodeStore) SaveAuthCode(ctx context.Context, code *entity.AuthCode) error {
	if m.authCodes == nil {
		m.authCodes = make(map[string]*entity.AuthCode)
	}
	m.authCodes[code.Code] = code
	return nil
}

func (m *MockAuthCodeStore) GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error) {
	authCode, exists := m.authCodes[code]
	if !exists {
		return nil, entity.ErrAuthCodeNotFound
	}
	return authCode, nil
}

func (m *MockAuthCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	delete(m.authCodes, code)
	return nil
}

type MockNonceStore struct {
	seenNonces map[string]bool
}

func (m *MockNonceStore) MarkNonceSeen(ctx context.Context, nonce, clientID string) error {
	if m.seenNonces == nil {
		m.seenNonces = make(map[string]bool)
	}
	key := clientID + ":" + nonce
	if m.seenNonces[key] {
		return entity.ErrNonceAlreadySeen
	}
	m.seenNonces[key] = true
	return nil
}

func TestAuthorize_NoAuthenticationHeader_Returns401(t *testing.T) {
	clientStore := &MockClientStore{
		clients: map[string]*entity.Client{
			"test-client": {
				ID:           "test-client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
		},
	}
	userinfoProvider := &MockUserinfoProvider{}
	authCodeStore := &MockAuthCodeStore{}
	nonceStore := &MockNonceStore{}

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	req := &AuthorizeRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
		State:        "test-state",
		// UserID is empty - simulating no authentication
	}

	result, errType, err := service.Authorize(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, ErrorAccessDenied, errType)
	assert.Nil(t, result)
}

func TestAuthorize_MissingRequiredParams_ReturnsError(t *testing.T) {
	clientStore := &MockClientStore{}
	userinfoProvider := &MockUserinfoProvider{}
	authCodeStore := &MockAuthCodeStore{}
	nonceStore := &MockNonceStore{}

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	tests := []struct {
		name string
		req  *AuthorizeRequest
	}{
		{
			name: "missing client_id",
			req: &AuthorizeRequest{
				RedirectURI:  "https://example.com/callback",
				ResponseType: "code",
				Scope:        "openid",
				State:        "test-state",
				UserID:       "user-123",
			},
		},
		{
			name: "missing redirect_uri",
			req: &AuthorizeRequest{
				ClientID:     "test-client",
				ResponseType: "code",
				Scope:        "openid",
				State:        "test-state",
				UserID:       "user-123",
			},
		},
		{
			name: "missing response_type",
			req: &AuthorizeRequest{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				Scope:       "openid",
				State:       "test-state",
				UserID:      "user-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, errType, err := service.Authorize(context.Background(), tt.req)

			require.NoError(t, err)
			assert.Equal(t, ErrorInvalidRequest, errType)
			assert.Nil(t, result)
		})
	}
}

func TestAuthorize_RedirectURIMismatch_ReturnsError(t *testing.T) {
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

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	req := &AuthorizeRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://evil.com/callback", // Mismatch
		ResponseType: "code",
		Scope:        "openid",
		State:        "test-state",
		UserID:       "user-123",
	}

	result, errType, err := service.Authorize(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidRedirectURI, errType)
	assert.Nil(t, result)
}

func TestAuthorize_ValidRequest_ReturnsCode(t *testing.T) {
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

	service := NewService(clientStore, userinfoProvider, authCodeStore, nonceStore)

	req := &AuthorizeRequest{
		ClientID:     "test-client",
		RedirectURI:  "https://example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
		State:        "test-state",
		UserID:       "user-123",
	}

	result, errType, err := service.Authorize(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, ErrorNone, errType)
	assert.NotNil(t, result)
	assert.Contains(t, result.RedirectURL, "code=")
	assert.Contains(t, result.RedirectURL, "state=test-state")
}
