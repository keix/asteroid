package oidc

import "errors"

// OIDC Authorization Errors (RFC 6749 Section 4.1.2.1)
type OIDCError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func NewOIDCError(code, description string) *OIDCError {
	return &OIDCError{
		Code:        code,
		Description: description,
	}
}

func (e *OIDCError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// RFC 6749 Standard Errors
var (
	ErrInvalidRequest          = NewOIDCError("invalid_request", "The request is missing a required parameter or includes an invalid parameter value")
	ErrUnauthorizedClient      = NewOIDCError("unauthorized_client", "The client is not authorized to request an authorization code using this method")
	ErrAccessDenied            = NewOIDCError("access_denied", "The resource owner or authorization server denied the request")
	ErrUnsupportedResponseType = NewOIDCError("unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method")
	ErrInvalidScope            = NewOIDCError("invalid_scope", "The requested scope is invalid, unknown, or malformed")
	ErrServerError             = NewOIDCError("server_error", "The authorization server encountered an unexpected condition")
	ErrTemporarilyUnavailable  = NewOIDCError("temporarily_unavailable", "The authorization server is currently unable to handle the request")
)

// Internal Domain Errors (not exposed directly to client)
var (
	ErrInvalidClient      = errors.New("invalid client")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
	ErrUserNotFound       = errors.New("user not found")
	ErrAuthCodeExpired    = errors.New("authorization code expired")
	ErrAuthCodeUsed       = errors.New("authorization code already used")
)
