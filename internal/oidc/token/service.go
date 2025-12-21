package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"asteroid/internal/oidc/signing"
	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"asteroid/internal/userinfo"
)

// Service handles token business logic
type Service struct {
	AuthCodeStore    store.AuthCodeStore
	TokenStore       store.TokenStore
	ClientStore      store.ClientStore
	SigningService   *signing.Service
	UserinfoProvider userinfo.Provider
	Issuer           string
}

// NewService creates a new token service
func NewService(
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	clientStore store.ClientStore,
	signingService *signing.Service,
	userinfoProvider userinfo.Provider,
	issuer string,
) *Service {
	return &Service{
		AuthCodeStore:    authCodeStore,
		TokenStore:       tokenStore,
		ClientStore:      clientStore,
		SigningService:   signingService,
		UserinfoProvider: userinfoProvider,
		Issuer:           issuer,
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
	CodeVerifier string
	AuthMethod   string // client_secret_post or client_secret_basic
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
	// OIDC Core 1.0 Token Endpoint Validation Order
	// Following RFC 6749 + OIDC Core security requirements
	//
	// Reject early — validate lightweight parameters first,
	// defer costly operations (like DB reads or signature work) to the end.
	//
	// 1. Request parameters
	// 2. Client authentication
	// 3. Authorization code validation
	// 4. PKCE validation
	// 5. Token generation
	// 6. ID Token creation with proper claim validation

	// Step 1: Request Parameter Validation (OIDC Core 3.1.3.1)
	if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// Step 2: Client Authentication (OIDC Core 3.1.3.1 + RFC 6749 3.2.1)
	// Must validate client identity BEFORE processing authorization code
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// Client authentication (client_secret_post, client_secret_basic, etc.)
	if err := s.validateClientAuthentication(client, req); err != nil {
		return nil, ErrorInvalidClient, nil
	}

	// Step 3: Authorization Code Validation (OIDC Core 3.1.3.1)
	authCode, err := s.AuthCodeStore.GetAuthCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, entity.ErrAuthCodeNotFound) {
			return nil, ErrorInvalidGrant, nil
		}
		return nil, 0, err
	}

	// Authorization code security validations (order matters for early rejection)
	// 3a. Client ID binding (equivalent to audience validation)
	if authCode.ClientID != req.ClientID {
		return nil, ErrorInvalidGrant, nil
	}
	// 3b. Redirect URI binding
	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrorInvalidGrant, nil
	}
	// 3c. Temporal validity (equivalent to expiration validation)
	now := time.Now()
	if now.After(authCode.ExpiresAt) {
		return nil, ErrorInvalidGrant, nil
	}

	// Step 4: PKCE Validation (RFC 7636)
	// Proof Key for Code Exchange validation - mandatory for public clients
	if client.IsPublicClient() {
		// Public clients MUST use PKCE
		if authCode.CodeChallenge == "" {
			return nil, ErrorInvalidGrant, nil // No PKCE challenge stored
		}
		if req.CodeVerifier == "" {
			return nil, ErrorInvalidRequest, nil // No code_verifier provided
		}
		if !validatePKCE(authCode.CodeChallenge, req.CodeVerifier, authCode.CodeChallengeMethod) {
			return nil, ErrorInvalidGrant, nil // PKCE validation failed
		}
	} else {
		// Confidential clients: PKCE is optional but must be validated if present
		if authCode.CodeChallenge != "" {
			if req.CodeVerifier == "" {
				return nil, ErrorInvalidRequest, nil
			}
			if !validatePKCE(authCode.CodeChallenge, req.CodeVerifier, authCode.CodeChallengeMethod) {
				return nil, ErrorInvalidGrant, nil
			}
		}
	}

	// Step 4.5: User Existence Verification
	// Verify user still exists before generating tokens
	_, err = s.UserinfoProvider.Fetch(ctx, authCode.UserID)
	if err != nil {
		if errors.Is(err, userinfo.ErrUserNotFound) {
			return nil, ErrorInvalidGrant, nil
		}
		return nil, 0, err
	}

	// Delete used authorization code
	if err := s.AuthCodeStore.DeleteAuthCode(ctx, req.Code); err != nil {
		return nil, 0, err
	}

	// Step 5: Token Generation
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	// Use consistent timestamp throughout the request

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

	result := &Result{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}

	// Step 6: ID Token Generation (OIDC Core 3.1.3.6)
	// Generate ID Token if openid scope is requested
	if strings.Contains(authCode.Scope, "openid") {
		idToken, err := s.generateIDToken(authCode.UserID, authCode.ClientID, authCode.Nonce, now)
		if err != nil {
			return nil, 0, err
		}
		result.IDToken = idToken
	}

	return result, 0, nil
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

	// Validate client authentication
	if err := s.validateClientAuthentication(client, req); err != nil {
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

	// User Existence Verification
	// Verify user still exists before refreshing tokens
	_, err = s.UserinfoProvider.Fetch(ctx, refreshTokenEntity.UserID)
	if err != nil {
		if errors.Is(err, userinfo.ErrUserNotFound) {
			return nil, ErrorInvalidGrant, nil
		}
		return nil, 0, err
	}

	// Delete old refresh token
	if err := s.TokenStore.DeleteRefreshToken(ctx, req.RefreshToken); err != nil {
		return nil, 0, err
	}

	// Generate new tokens
	accessToken := uuid.NewString()
	refreshToken := uuid.NewString()
	now := time.Now()

	accessTokenEntity := &entity.AccessToken{
		Token:     accessToken,
		ClientID:  refreshTokenEntity.ClientID,
		UserID:    refreshTokenEntity.UserID,
		Scope:     refreshTokenEntity.Scope,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	newRefreshTokenEntity := &entity.RefreshToken{
		Token:     refreshToken,
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

	result := &Result{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: refreshToken,
		Scope:        refreshTokenEntity.Scope,
	}

	// Generate ID Token if openid scope is requested
	if strings.Contains(refreshTokenEntity.Scope, "openid") {
		// NOTE: nonce is empty for refresh token grant (nonce only applies to authorization request)
		idToken, err := s.generateIDToken(refreshTokenEntity.UserID, refreshTokenEntity.ClientID, "", now)
		if err != nil {
			return nil, 0, err
		}
		result.IDToken = idToken
	}

	return result, 0, nil
}

// validateClientAuthentication validates client credentials and authentication method
func (s *Service) validateClientAuthentication(client *entity.Client, req *TokenRequest) error {
	// Public clients don't require client secret authentication
	if client.IsPublicClient() {
		// For public clients, PKCE is mandatory (enforced at authorization level)
		// No client secret validation required
		return nil
	}

	// Confidential clients require client secret
	if client.Secret != req.ClientSecret {
		return errors.New("invalid client secret")
	}

	// Default to client_secret_post if no method specified (backward compatibility)
	clientAuthMethod := client.TokenEndpointAuthMethod
	if clientAuthMethod == "" {
		clientAuthMethod = "client_secret_post"
	}

	// Validate authentication method
	requestAuthMethod := req.AuthMethod
	if requestAuthMethod == "" {
		requestAuthMethod = "client_secret_post" // default
	}

	// Check if client supports the requested authentication method
	if clientAuthMethod != requestAuthMethod {
		return errors.New("authentication method not supported for this client")
	}

	return nil
}

// generateIDToken creates an ID token using the signing service
// Uses current timestamp for both issuance and authentication time
func (s *Service) generateIDToken(userID, clientID, nonce string, now time.Time) (string, error) {
	// Get active signing key for ES256 algorithm
	// Note: ES256 is Asteroid's current algorithm choice for performance and security
	activeKey, err := s.SigningService.GetActiveKey("ES256")
	if err != nil {
		return "", fmt.Errorf("failed to get active signing key: %w", err)
	}

	// Create claims following OIDC Core validation order
	claims := jwt.MapClaims{
		"iss": s.Issuer,                      // Step 1: Issuer validation by clients
		"sub": userID,                        // Subject identifier
		"aud": clientID,                      // Step 2: Audience validation by clients
		"exp": now.Add(1 * time.Hour).Unix(), // Step 3: Expiration validation
		"iat": now.Unix(),                    // Issued at time
	}

	// Add nonce if provided
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = activeKey.KeyID

	// Sign token
	return token.SignedString(activeKey.PrivateKey)
}
