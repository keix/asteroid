package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"asteroid/internal/clock"
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
	Clock            clock.Clock
	Generator        clock.Generator
}

// NewService creates a new token service
func NewService(
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	clientStore store.ClientStore,
	signingService *signing.Service,
	userinfoProvider userinfo.Provider,
	issuer string,
	clk clock.Clock,
	gen clock.Generator,
) *Service {
	return &Service{
		AuthCodeStore:    authCodeStore,
		TokenStore:       tokenStore,
		ClientStore:      clientStore,
		SigningService:   signingService,
		UserinfoProvider: userinfoProvider,
		Issuer:           issuer,
		Clock:            clk,
		Generator:        gen,
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
	Audience     string
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
	case "client_credentials":
		return s.clientCredentials(ctx, req)
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

	// Grant-type policy check
	if !client.IsGrantTypeAllowed("authorization_code") {
		return nil, ErrorUnauthorizedClient, nil
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
	now := s.Clock.Now()
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
	accessToken := s.Generator.NewToken()
	refreshToken := s.Generator.NewToken()
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
		AuthTime:  authCode.AuthTime,
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
		idToken, err := s.generateIDToken(authCode.UserID, authCode.ClientID, authCode.Nonce, authCode.AuthTime, now)
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

	// Grant-type policy check
	if !client.IsGrantTypeAllowed("refresh_token") {
		return nil, ErrorUnauthorizedClient, nil
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
	accessToken := s.Generator.NewToken()
	refreshToken := s.Generator.NewToken()
	now := s.Clock.Now()

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
		AuthTime:  refreshTokenEntity.AuthTime,
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
		idToken, err := s.generateIDToken(refreshTokenEntity.UserID, refreshTokenEntity.ClientID, "", refreshTokenEntity.AuthTime, now)
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

// clientCredentials implements the OAuth 2.0 client credentials grant (RFC 6749 §4.4)
// and mints a JWT access token per RFC 9068.
func (s *Service) clientCredentials(ctx context.Context, req *TokenRequest) (*Result, ErrorType, error) {
	// 1. Request parameter validation
	if req.ClientID == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// 2. Client lookup
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// 3. Public clients are not permitted to use client_credentials
	if client.IsPublicClient() {
		return nil, ErrorInvalidClient, nil
	}

	// 4. Client authentication (secret required for confidential clients)
	if err := s.validateClientAuthentication(client, req); err != nil {
		return nil, ErrorInvalidClient, nil
	}

	// 5. Grant-type policy check
	if !client.IsGrantTypeAllowed("client_credentials") {
		return nil, ErrorUnauthorizedClient, nil
	}

	// 6. Resolve audience against the client's allowlist
	audience, errType := resolveAudience(client, req.Audience)
	if errType != ErrorNone {
		return nil, errType, nil
	}

	// 7. Resolve scopes against the client's allowlist
	grantedScopes, errType := resolveScopes(client, req.Scope)
	if errType != ErrorNone {
		return nil, errType, nil
	}
	scopeStr := strings.Join(grantedScopes, " ")

	// 8. Mint JWT access token
	now := s.Clock.Now()
	jti := s.Generator.NewToken()
	accessToken, err := s.generateJWTAccessToken(client.ID, audience, scopeStr, jti, now)
	if err != nil {
		return nil, 0, err
	}

	return &Result{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scopeStr,
	}, ErrorNone, nil
}

// resolveAudience validates and resolves the requested audience against the client's allowlist.
// Returns invalid_request when the client has no configured audience for client_credentials,
// or when the client has multiple entries and none was requested.
// Returns invalid_target when the requested audience is not in the allowlist.
func resolveAudience(client *entity.Client, requested string) (string, ErrorType) {
	if len(client.AllowedAudiences) == 0 {
		return "", ErrorInvalidRequest
	}
	if requested == "" {
		if len(client.AllowedAudiences) == 1 {
			return client.AllowedAudiences[0], ErrorNone
		}
		return "", ErrorInvalidRequest
	}
	for _, aud := range client.AllowedAudiences {
		if aud == requested {
			return requested, ErrorNone
		}
	}
	return "", ErrorInvalidTarget
}

// resolveScopes validates the requested scopes against the client's allowlist.
// When no scope is requested, the full allowlist is granted.
// An empty allowlist means no scopes may be granted; a scoped request against it fails.
func resolveScopes(client *entity.Client, requested string) ([]string, ErrorType) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return client.AllowedScopes, ErrorNone
	}
	if len(client.AllowedScopes) == 0 {
		return nil, ErrorInvalidScope
	}
	allowed := make(map[string]struct{}, len(client.AllowedScopes))
	for _, s := range client.AllowedScopes {
		allowed[s] = struct{}{}
	}
	parts := strings.Fields(requested)
	for _, p := range parts {
		if _, ok := allowed[p]; !ok {
			return nil, ErrorInvalidScope
		}
	}
	return parts, ErrorNone
}

// generateJWTAccessToken creates an RFC 9068 JWT access token signed with the active ES256 key.
func (s *Service) generateJWTAccessToken(clientID, audience, scope, jti string, now time.Time) (string, error) {
	activeKey, err := s.SigningService.GetActiveKey("ES256")
	if err != nil {
		return "", fmt.Errorf("failed to get active signing key: %w", err)
	}

	claims := jwt.MapClaims{
		"iss":       s.Issuer,
		"sub":       clientID,
		"aud":       audience,
		"exp":       now.Add(1 * time.Hour).Unix(),
		"iat":       now.Unix(),
		"client_id": clientID,
		"token_use": "access",
		"jti":       jti,
	}
	if scope != "" {
		claims["scope"] = scope
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = activeKey.KeyID
	return token.SignedString(activeKey.PrivateKey)
}

// generateIDToken creates an ID token using the signing service
func (s *Service) generateIDToken(userID, clientID, nonce string, authTime, now time.Time) (string, error) {
	activeKey, err := s.SigningService.GetActiveKey("RS256")
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
	if !authTime.IsZero() {
		claims["auth_time"] = authTime.Unix()
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKey.KeyID

	// Sign token
	return token.SignedString(activeKey.PrivateKey)
}
