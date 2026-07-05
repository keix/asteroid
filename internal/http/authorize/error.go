package authorize

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"asteroid/internal/oidc/authorize"
)

// OIDCError represents RFC 6749 standard errors for HTTP responses
type OIDCError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func newOIDCError(code, description string) *OIDCError {
	return &OIDCError{
		Code:        code,
		Description: description,
	}
}

// RFC 6749 Standard Errors
var (
	errInvalidRequest          = newOIDCError("invalid_request", "The request is missing a required parameter or includes an invalid parameter value")
	errUnauthorizedClient      = newOIDCError("unauthorized_client", "The client is not authorized to request an authorization code using this method")
	errAccessDenied            = newOIDCError("access_denied", "The resource owner or authorization server denied the request")
	errUnsupportedResponseType = newOIDCError("unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method")
	errInvalidScope            = newOIDCError("invalid_scope", "The requested scope is invalid, unknown, or malformed")
	errServerError             = newOIDCError("server_error", "The authorization server encountered an unexpected condition")
)

// HandleDomainError handles domain errors and converts them to HTTP responses
func HandleDomainError(c *gin.Context, errType authorize.ErrorType, req *Request) {
	oidcErr := mapToOIDCError(errType)

	// If we have a valid redirect_uri, redirect with error (RFC 6749 Section 4.1.2.1)
	if req.RedirectURI != "" &&
		errType != authorize.ErrorInvalidRequestNoRedirect &&
		errType != authorize.ErrorInvalidClient &&
		errType != authorize.ErrorInvalidRedirectURI {
		redirectWithError(c, req.RedirectURI, oidcErr, req.State)
		return
	}

	// Otherwise return JSON error response
	status := getHTTPStatusFromOIDCError(oidcErr.Code)
	c.JSON(status, oidcErr)
}

// HandleSystemError handles system errors
func HandleSystemError(c *gin.Context, err error, req *Request) {
	oidcErr := errServerError

	// System errors are always returned as JSON (don't redirect)
	c.JSON(http.StatusInternalServerError, oidcErr)
}

// mapToOIDCError maps domain errors to RFC 6749 OIDC errors
func mapToOIDCError(errType authorize.ErrorType) *OIDCError {
	switch errType {
	case authorize.ErrorInvalidRequest:
		return errInvalidRequest
	case authorize.ErrorInvalidRequestNoRedirect:
		return errInvalidRequest
	case authorize.ErrorInvalidClient:
		return errUnauthorizedClient // Per industry practice (Auth0, Okta, Keycloak)
	case authorize.ErrorInvalidRedirectURI:
		return errInvalidRequest
	case authorize.ErrorUnsupportedResponse:
		return errUnsupportedResponseType
	case authorize.ErrorInvalidScope:
		return errInvalidScope
	case authorize.ErrorAccessDenied:
		return errAccessDenied
	case authorize.ErrorServerError:
		return errServerError
	default:
		return errServerError
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
	default:
		return http.StatusInternalServerError
	}
}
