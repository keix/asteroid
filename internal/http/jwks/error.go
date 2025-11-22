package jwks

import (
	"net/http"

	"github.com/gin-gonic/gin"
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

// Standard errors for JWKS endpoint
var (
	errServerError = newOIDCError("server_error", "The authorization server encountered an unexpected condition")
)

// HandleSystemError handles system errors for JWKS endpoint
func HandleSystemError(c *gin.Context, err error) {
	// Log the actual error internally (in production, use proper logging)
	// log.Printf("JWKS system error: %v", err)

	// Return standardized error to client
	c.JSON(http.StatusInternalServerError, errServerError)
}
