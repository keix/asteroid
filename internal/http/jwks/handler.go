package jwks

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/oidc/jwks"
	"asteroid/internal/oidc/signing"
)

// Handler handles HTTP requests for JWKS endpoint
type Handler struct {
	service *jwks.Service
}

// NewHandler creates a new JWKS handler
func NewHandler(signingService *signing.Service) *Handler {
	return &Handler{
		service: jwks.NewService(signingService),
	}
}

// Handle processes JWKS HTTP requests
func (h *Handler) Handle(c *gin.Context) {
	jwkSet, err := h.service.GetJWKSet(c.Request.Context())
	if err != nil {
		// System error
		HandleSystemError(c, err)
		return
	}

	// Success - return JWK Set
	c.JSON(http.StatusOK, jwkSet)
}
