package authorize

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"asteroid/internal/userinfo"
)

// Service handles authorization business logic
type Service struct {
	ClientStore      store.ClientStore
	UserinfoProvider userinfo.Provider
	AuthCodeStore    store.AuthCodeStore
	NonceStore       store.NonceStore
	Clock            clock.Clock
	Generator        clock.Generator
}

// NewService creates a new authorization service
func NewService(
	clientStore store.ClientStore,
	userinfoProvider userinfo.Provider,
	authCodeStore store.AuthCodeStore,
	nonceStore store.NonceStore,
	clk clock.Clock,
	gen clock.Generator,
) *Service {
	return &Service{
		ClientStore:      clientStore,
		UserinfoProvider: userinfoProvider,
		AuthCodeStore:    authCodeStore,
		NonceStore:       nonceStore,
		Clock:            clk,
		Generator:        gen,
	}
}

// AuthorizeRequest represents the data needed for authorization
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string // From X-Authenticated-User header
}

// Authorize processes authorization request (pure business logic)
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (*Result, ErrorType, error) {
	// A redirect is safe only after both the client and redirect URI have been
	// validated.
	if req.ClientID == "" || req.RedirectURI == "" {
		return nil, ErrorInvalidRequestNoRedirect, nil
	}

	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	if !validateExactRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, ErrorInvalidRedirectURI, nil
	}

	if req.ResponseType == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// SECURITY: State parameter is mandatory for CSRF protection (OIDC best practice)
	if req.State == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// SECURITY: Nonce replay protection (prevents ID token replay attacks)
	if req.Nonce != "" {
		err := s.NonceStore.MarkNonceSeen(ctx, req.Nonce, req.ClientID)
		if errors.Is(err, entity.ErrNonceAlreadySeen) {
			return nil, ErrorInvalidRequest, nil
		} else if err != nil {
			return nil, 0, err
		}
	}

	// Validate response_type
	if req.ResponseType != "code" {
		return nil, ErrorUnsupportedResponse, nil
	}

	// Validate scope
	if req.Scope != "openid" {
		return nil, ErrorInvalidScope, nil
	}

	// SECURITY: PKCE (RFC 7636) validation and enforcement
	if err := s.validatePKCEForClient(client, req); err != nil {
		return nil, ErrorInvalidRequest, nil
	}

	// Validate authenticated user exists (from X-Authenticated-User header)
	if req.UserID == "" {
		return nil, ErrorAccessDenied, nil
	}

	_, err = s.UserinfoProvider.Fetch(ctx, req.UserID)
	if err != nil {
		if errors.Is(err, userinfo.ErrUserNotFound) {
			return nil, ErrorAccessDenied, nil
		}
		return nil, 0, err
	}

	// Generate authorization code
	code := s.Generator.NewCode()
	now := s.Clock.Now()
	authCode := &entity.AuthCode{
		Code:                code,
		ClientID:            client.ID,
		UserID:              req.UserID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		AuthTime:            now,
		ExpiresAt:           now.Add(5 * time.Minute),
	}

	if err := s.AuthCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return nil, 0, err
	}

	redirectURI, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, 0, err
	}
	params := redirectURI.Query()
	params.Set("code", code)
	if req.State != "" {
		params.Set("state", req.State)
	}
	redirectURI.RawQuery = params.Encode()

	return &Result{RedirectURL: redirectURI.String()}, ErrorNone, nil
}

// validateExactRedirectURI performs RFC 6749 compliant exact redirect URI validation
// SECURITY: Uses string comparison to prevent URL normalization attacks
func validateExactRedirectURI(registeredURIs []string, requestedURI string) bool {
	return slices.Contains(registeredURIs, requestedURI)
}

// validatePKCEForClient validates PKCE requirements based on client type
func (s *Service) validatePKCEForClient(client *entity.Client, req *AuthorizeRequest) error {
	// For public clients, PKCE is mandatory
	if client.IsPublicClient() {
		if req.CodeChallenge == "" {
			return errors.New("PKCE required for public clients")
		}
		// Basic validation - detailed format checking done elsewhere
		if req.CodeChallengeMethod != "S256" {
			return errors.New("only S256 method supported for PKCE")
		}
		return nil
	}

	// For confidential clients, PKCE is optional
	// If provided, format validation is handled by existing logic
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return errors.New("only S256 method supported for PKCE")
	}

	return nil
}
