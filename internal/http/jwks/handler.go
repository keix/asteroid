package jwks

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/oidc/jwks"
	"asteroid/internal/store"
)

// Handler handles HTTP requests for JWKS endpoint
type Handler struct {
	service *jwks.Service
}

// NewHandler creates a new JWKS handler
func NewHandler(keyStore store.KeyStore) *Handler {
	return &Handler{
		service: jwks.NewService(keyStore),
	}
}

// Handle processes JWKS HTTP requests
func (h *Handler) Handle(c *gin.Context) {
	jwkSet, err := h.service.GetJWKSet(c.Request.Context())
	if err != nil {
		// System error - return generic server error
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get signing key",
		})
		return
	}

	// Success - return JWK Set
	c.JSON(http.StatusOK, jwkSet)
}
