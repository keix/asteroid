package token

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/oidc/token"
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

// RFC 6749 Standard Token Errors
var (
	errInvalidRequest       = newOIDCError("invalid_request", "The request is missing a required parameter or includes an invalid parameter value")
	errInvalidClient        = newOIDCError("invalid_client", "Client authentication failed")
	errInvalidGrant         = newOIDCError("invalid_grant", "The provided authorization grant is invalid, expired, revoked, or malformed")
	errUnauthorizedClient   = newOIDCError("unauthorized_client", "The authenticated client is not authorized to use this authorization grant type")
	errUnsupportedGrantType = newOIDCError("unsupported_grant_type", "The authorization grant type is not supported by the authorization server")
	errInvalidScope         = newOIDCError("invalid_scope", "The requested scope is invalid, unknown, or malformed")
	errServerError          = newOIDCError("server_error", "The authorization server encountered an unexpected condition")
)

// HandleDomainError handles domain errors and converts them to HTTP responses
func HandleDomainError(c *gin.Context, errType token.ErrorType, req *Request) {
	oidcErr := mapToOIDCError(errType)
	status := getHTTPStatusFromOIDCError(oidcErr.Code)
	c.JSON(status, oidcErr)
}

// HandleSystemError handles system errors
func HandleSystemError(c *gin.Context, err error, req *Request) {
	oidcErr := errServerError
	c.JSON(http.StatusInternalServerError, oidcErr)
}

// mapToOIDCError maps domain errors to RFC 6749 OIDC errors
func mapToOIDCError(errType token.ErrorType) *OIDCError {
	switch errType {
	case token.ErrorInvalidRequest:
		return errInvalidRequest
	case token.ErrorInvalidClient:
		return errInvalidClient
	case token.ErrorInvalidGrant:
		return errInvalidGrant
	case token.ErrorUnauthorizedClient:
		return errUnauthorizedClient
	case token.ErrorUnsupportedGrantType:
		return errUnsupportedGrantType
	case token.ErrorInvalidScope:
		return errInvalidScope
	case token.ErrorServerError:
		return errServerError
	default:
		return errServerError
	}
}

// getHTTPStatusFromOIDCError maps OIDC error codes to HTTP status codes
func getHTTPStatusFromOIDCError(errorCode string) int {
	switch errorCode {
	case "invalid_request", "invalid_grant", "unsupported_grant_type", "invalid_scope":
		return http.StatusBadRequest
	case "invalid_client", "unauthorized_client":
		return http.StatusUnauthorized
	case "server_error":
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}
