package wellknown

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/oidc/wellknown"
)

// Handler handles HTTP requests for OpenID Connect Discovery endpoint
type Handler struct {
	service *wellknown.Service
}

// NewHandler creates a new Well-known handler
func NewHandler(issuer string) *Handler {
	return &Handler{
		service: wellknown.NewService(issuer),
	}
}

// Handle processes OpenID Connect Discovery HTTP requests
func (h *Handler) Handle(c *gin.Context) {
	config := h.service.GetOpenIDConfiguration()

	// Success - return OpenID Configuration
	c.JSON(http.StatusOK, config)
}
