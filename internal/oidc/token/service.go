package token

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
)

// Service handles token business logic
type Service struct {
	AuthCodeStore store.AuthCodeStore
	TokenStore    store.TokenStore
	ClientStore   store.ClientStore
}

// NewService creates a new token service
func NewService(
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	clientStore store.ClientStore,
) *Service {
	return &Service{
		AuthCodeStore: authCodeStore,
		TokenStore:    tokenStore,
		ClientStore:   clientStore,
	}
}

// TokenRequest represents the data needed for token exchange
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
}

// ExchangeToken processes token request (pure business logic)
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*Result, ErrorType, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.exchangeAuthorizationCode(ctx, req)
	case "refresh_token":
		return s.refreshToken(ctx, req)
	default:
		return nil, ErrorUnsupportedGrantType, nil
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req *TokenRequest) (*Result, ErrorType, error) {
	// Validate required parameters
	if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// Get and validate client
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// Validate client secret
	if client.Secret != req.ClientSecret {
		return nil, ErrorInvalidClient, nil
	}

	// Get authorization code
	authCode, err := s.AuthCodeStore.GetAuthCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, entity.ErrAuthCodeNotFound) {
			return nil, ErrorInvalidGrant, nil
		}
		return nil, 0, err
	}

	// Validate authorization code
	if authCode.ClientID != req.ClientID {
		return nil, ErrorInvalidGrant, nil
	}
	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrorInvalidGrant, nil
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrorInvalidGrant, nil
	}

	// Delete used authorization code
	if err := s.AuthCodeStore.DeleteAuthCode(ctx, req.Code); err != nil {
		return nil, 0, err
	}

	// Generate tokens
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	now := time.Now()

	accessTokenEntity := &entity.AccessToken{
		Token:     accessToken,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scope:     authCode.Scope,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	refreshTokenEntity := &entity.RefreshToken{
		Token:     refreshToken,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scope:     authCode.Scope,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}

	// Save tokens
	if err := s.TokenStore.SaveAccessToken(ctx, accessTokenEntity); err != nil {
		return nil, 0, err
	}
	if err := s.TokenStore.SaveRefreshToken(ctx, refreshTokenEntity); err != nil {
		return nil, 0, err
	}

	return &Result{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}, 0, nil
}

func (s *Service) refreshToken(ctx context.Context, req *TokenRequest) (*Result, ErrorType, error) {
	// Validate required parameters
	if req.RefreshToken == "" || req.ClientID == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// Get and validate client
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// Validate client secret
	if client.Secret != req.ClientSecret {
		return nil, ErrorInvalidClient, nil
	}

	// Get refresh token
	refreshTokenEntity, err := s.TokenStore.GetRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, entity.ErrRefreshTokenNotFound) || errors.Is(err, entity.ErrRefreshTokenExpired) {
			return nil, ErrorInvalidGrant, nil
		}
		return nil, 0, err
	}

	// Validate refresh token belongs to client
	if refreshTokenEntity.ClientID != req.ClientID {
		return nil, ErrorInvalidGrant, nil
	}

	// Delete old refresh token
	if err := s.TokenStore.DeleteRefreshToken(ctx, req.RefreshToken); err != nil {
		return nil, 0, err
	}

	// Generate new tokens
	accessToken := uuid.NewString()
	newRefreshToken := uuid.NewString()
	now := time.Now()

	accessTokenEntity := &entity.AccessToken{
		Token:     accessToken,
		ClientID:  refreshTokenEntity.ClientID,
		UserID:    refreshTokenEntity.UserID,
		Scope:     refreshTokenEntity.Scope,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	newRefreshTokenEntity := &entity.RefreshToken{
		Token:     newRefreshToken,
		ClientID:  refreshTokenEntity.ClientID,
		UserID:    refreshTokenEntity.UserID,
		Scope:     refreshTokenEntity.Scope,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}

	// Save new tokens
	if err := s.TokenStore.SaveAccessToken(ctx, accessTokenEntity); err != nil {
		return nil, 0, err
	}
	if err := s.TokenStore.SaveRefreshToken(ctx, newRefreshTokenEntity); err != nil {
		return nil, 0, err
	}

	return &Result{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: newRefreshToken,
		Scope:        refreshTokenEntity.Scope,
	}, 0, nil
}
