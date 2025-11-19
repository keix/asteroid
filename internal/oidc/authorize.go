package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"asteroid/internal/store"
)

type AuthorizeHandler struct {
	ClientStore   store.ClientStore
	UserStore     store.UserStore
	AuthCodeStore store.AuthCodeStore
}

func NewAuthorizeHandler(
	clientStore store.ClientStore,
	userStore store.UserStore,
	authCodeStore store.AuthCodeStore,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		ClientStore:   clientStore,
		UserStore:     userStore,
		AuthCodeStore: authCodeStore,
	}
}

func (h *AuthorizeHandler) Handle(c *gin.Context) {
	req := NewAuthorizeRequest(c)

	result, authErr, err := h.HandleAuthorize(c.Request.Context(), req)
	if err != nil {
		// System error
		authErr := &AuthorizeError{
			Type:        AuthorizeErrorServerError,
			RedirectURI: req.RedirectURI,
			State:       req.State,
			Internal:    err,
		}
		handleAuthorizeError(c, authErr)
		return
	}

	if authErr != nil {
		// Domain error
		handleAuthorizeError(c, authErr)
		return
	}

	// Success
	c.Redirect(302, result.RedirectURL)
}

// HandleAuthorize processes authorization request (pure business logic)
func (h *AuthorizeHandler) HandleAuthorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResult, *AuthorizeError, error) {
	// Validate required parameters
	if req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
		return nil, &AuthorizeError{
			Type:        AuthorizeErrorInvalidRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}, nil
	}

	// Validate response_type
	if req.ResponseType != "code" {
		return nil, &AuthorizeError{
			Type:        AuthorizeErrorUnsupportedResponse,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}, nil
	}

	// Validate scope
	if req.Scope != "openid" {
		return nil, &AuthorizeError{
			Type:        AuthorizeErrorInvalidScope,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}, nil
	}

	// Get and validate client
	client, err := h.ClientStore.GetClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			return nil, &AuthorizeError{
				Type:        AuthorizeErrorInvalidClient,
				RedirectURI: req.RedirectURI,
				State:       req.State,
			}, nil
		}
		return nil, nil, err
	}

	// Validate redirect_uri
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return nil, &AuthorizeError{
			Type:        AuthorizeErrorInvalidRedirectURI,
			RedirectURI: "", // Don't redirect on invalid redirect_uri
			State:       req.State,
		}, nil
	}

	// Get user (simplified authentication)
	user, err := h.UserStore.GetUserByID(ctx, "user-123")
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return nil, &AuthorizeError{
				Type:        AuthorizeErrorAccessDenied,
				RedirectURI: req.RedirectURI,
				State:       req.State,
			}, nil
		}
		return nil, nil, err
	}

	// Generate authorization code
	code := uuid.NewString()
	authCode := &store.AuthCode{
		Code:        code,
		ClientID:    client.ID,
		UserID:      user.ID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := h.AuthCodeStore.SaveAuthCode(ctx, authCode); err != nil {
		return nil, nil, err
	}

	// Build success redirect URL
	redirectURL := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURL += "&state=" + req.State
	}

	return &AuthorizeResult{RedirectURL: redirectURL}, nil, nil
}

// handleAuthorizeError handles authorization errors and sends appropriate response
func handleAuthorizeError(c *gin.Context, authErr *AuthorizeError) {
	oidcErr := mapToOIDCError(authErr.Type)

	// If we have a valid redirect_uri, redirect with error (RFC 6749 Section 4.1.2.1)
	if authErr.RedirectURI != "" && authErr.Type != AuthorizeErrorInvalidRedirectURI {
		redirectWithError(c, authErr.RedirectURI, oidcErr, authErr.State)
		return
	}

	// Otherwise return JSON error response
	status := getHTTPStatusFromOIDCError(oidcErr.Code)
	c.JSON(status, oidcErr)
}

// mapToOIDCError maps domain errors to RFC 6749 OIDC errors
func mapToOIDCError(errType AuthorizeErrorType) *OIDCError {
	switch errType {
	case AuthorizeErrorInvalidRequest:
		return ErrInvalidRequest
	case AuthorizeErrorInvalidClient:
		return ErrUnauthorizedClient // Per industry practice (Auth0, Okta, Keycloak)
	case AuthorizeErrorInvalidRedirectURI:
		return ErrInvalidRequest
	case AuthorizeErrorUnsupportedResponse:
		return ErrUnsupportedResponseType
	case AuthorizeErrorInvalidScope:
		return ErrInvalidScope
	case AuthorizeErrorAccessDenied:
		return ErrAccessDenied
	case AuthorizeErrorServerError:
		return ErrServerError
	default:
		// TODO: Add proper error logging here
		return ErrServerError
	}
}

// redirectWithError redirects to client with error parameters
func redirectWithError(c *gin.Context, redirectURI string, oidcErr *OIDCError, state string) {
	params := url.Values{}
	params.Set("error", oidcErr.Code)

	if oidcErr.Description != "" {
		params.Set("error_description", oidcErr.Description)
	}

	if state != "" {
		params.Set("state", state)
	}

	// Build error redirect URL with proper encoding
	errorURL := redirectURI
	if len(params) > 0 {
		separator := "?"
		if containsQuery(redirectURI) {
			separator = "&"
		}
		errorURL += separator + params.Encode()
	}

	c.Redirect(http.StatusFound, errorURL)
}

// containsQuery checks if URL already contains query parameters
func containsQuery(urlStr string) bool {
	return strings.Contains(urlStr, "?")
}

// getHTTPStatusFromOIDCError maps OIDC error codes to HTTP status codes
func getHTTPStatusFromOIDCError(errorCode string) int {
	switch errorCode {
	case "invalid_request", "unsupported_response_type", "invalid_scope":
		return http.StatusBadRequest
	case "unauthorized_client":
		return http.StatusUnauthorized
	case "access_denied":
		return http.StatusForbidden
	case "server_error":
		return http.StatusInternalServerError
	case "temporarily_unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
