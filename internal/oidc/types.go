package oidc

import "github.com/gin-gonic/gin"

// AuthorizeRequest represents an OAuth 2.0 authorization request
type AuthorizeRequest struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
}

// NewAuthorizeRequest creates AuthorizeRequest from gin.Context
func NewAuthorizeRequest(c *gin.Context) *AuthorizeRequest {
	return &AuthorizeRequest{
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		ResponseType: c.Query("response_type"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),
	}
}

// AuthorizeResult represents the result of authorization processing
type AuthorizeResult struct {
	RedirectURL string
}

// AuthorizeError represents domain-specific authorization errors
type AuthorizeError struct {
	Type        AuthorizeErrorType
	RedirectURI string
	State       string
	Internal    error
}

func (e *AuthorizeError) Error() string {
	if e.Internal != nil {
		return e.Internal.Error()
	}
	return string(e.Type)
}

type AuthorizeErrorType string

const (
	AuthorizeErrorInvalidRequest      AuthorizeErrorType = "invalid_request"
	AuthorizeErrorInvalidClient       AuthorizeErrorType = "invalid_client"
	AuthorizeErrorInvalidRedirectURI  AuthorizeErrorType = "invalid_redirect_uri"
	AuthorizeErrorUnsupportedResponse AuthorizeErrorType = "unsupported_response_type"
	AuthorizeErrorInvalidScope        AuthorizeErrorType = "invalid_scope"
	AuthorizeErrorAccessDenied        AuthorizeErrorType = "access_denied"
	AuthorizeErrorServerError         AuthorizeErrorType = "server_error"
)
