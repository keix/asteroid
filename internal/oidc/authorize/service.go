package authorize

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
)

// Service handles authorization business logic
type Service struct {
	ClientStore   store.ClientStore
	UserStore     store.UserStore
	AuthCodeStore store.AuthCodeStore
	NonceStore    store.NonceStore
}

// NewService creates a new authorization service
func NewService(
	clientStore store.ClientStore,
	userStore store.UserStore,
	authCodeStore store.AuthCodeStore,
	nonceStore store.NonceStore,
) *Service {
	return &Service{
		ClientStore:   clientStore,
		UserStore:     userStore,
		AuthCodeStore: authCodeStore,
		NonceStore:    nonceStore,
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
}

// Authorize processes authorization request (pure business logic)
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (*Result, ErrorType, error) {
	// Validate required parameters
	if req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
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

	// SECURITY: PKCE (RFC 7636) validation for code interception protection
	if req.CodeChallenge != "" {
		// If code_challenge is provided, code_challenge_method is required
		if req.CodeChallengeMethod == "" {
			return nil, ErrorInvalidRequest, nil
		}
		// Only S256 method is allowed for security (reject plain and unknown methods)
		if req.CodeChallengeMethod != "S256" {
			return nil, ErrorInvalidRequest, nil
		}
	}

	// Get and validate client
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// SECURITY NOTE:
	// Do not perform redirect_uri validation in the HTTP handler.
	// OAuth2/OIDC redirect_uri matching is protocol logic, not transport logic.
	// Keeping this validation inside the authorization service ensures consistency
	// across all entry points and improves auditability.
	if !validateExactRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, ErrorInvalidRedirectURI, nil
	}

	// Get user (simplified authentication)
	user, err := s.UserStore.GetUserByID(ctx, "user-123")
	if err != nil {
		if errors.Is(err, entity.ErrUserNotFound) {
			return nil, ErrorAccessDenied, nil
		}
		return nil, 0, err
	}

	// Generate authorization code
	code := uuid.NewString()
	authCode := &entity.AuthCode{
		Code:                code,
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	if err := s.AuthCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return nil, 0, err
	}

	// Build success redirect URL
	redirectURL := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}

	return &Result{RedirectURL: redirectURL}, ErrorNone, nil
}

// validateExactRedirectURI performs RFC 6749 compliant exact redirect URI validation
// SECURITY: Uses string comparison to prevent URL normalization attacks
func validateExactRedirectURI(registeredURIs []string, requestedURI string) bool {
	return slices.Contains(registeredURIs, requestedURI)
}
