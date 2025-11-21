package authorize

import (
	"context"
	"errors"
	"fmt"
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
}

// NewService creates a new authorization service
func NewService(
	clientStore store.ClientStore,
	userStore store.UserStore,
	authCodeStore store.AuthCodeStore,
) *Service {
	return &Service{
		ClientStore:   clientStore,
		UserStore:     userStore,
		AuthCodeStore: authCodeStore,
	}
}

// AuthorizeRequest represents the data needed for authorization
type AuthorizeRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        string
	State        string
}

// Authorize processes authorization request (pure business logic)
func (s *Service) Authorize(ctx context.Context, req *AuthorizeRequest) (*Result, ErrorType, error) {
	// Validate required parameters
	if req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
		return nil, ErrorInvalidRequest, nil
	}

	// Validate response_type
	if req.ResponseType != "code" {
		return nil, ErrorUnsupportedResponse, nil
	}

	// Validate scope
	if req.Scope != "openid" {
		return nil, ErrorInvalidScope, nil
	}

	// Get and validate client
	client, err := s.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, entity.ErrClientNotFound) {
			return nil, ErrorInvalidClient, nil
		}
		return nil, 0, err
	}

	// Validate redirect_uri
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
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
		Code:        code,
		ClientID:    client.ID,
		UserID:      user.ID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := s.AuthCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return nil, 0, err
	}

	// Build success redirect URL
	redirectURL := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}

	return &Result{RedirectURL: redirectURL}, 0, nil
}
