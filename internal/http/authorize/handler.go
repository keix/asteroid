package authorize

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/clock"
	"asteroid/internal/oidc/authorize"
	"asteroid/internal/store"
	"asteroid/internal/userinfo"
)

// Handler handles HTTP requests for authorization endpoint
type Handler struct {
	service *authorize.Service
}

// NewHandler creates a new authorization handler
func NewHandler(
	clientStore store.ClientStore,
	authCodeStore store.AuthCodeStore,
	nonceStore store.NonceStore,
	userinfoProvider userinfo.Provider,
) *Handler {
	return &Handler{
		service: authorize.NewService(
			clientStore,
			userinfoProvider,
			authCodeStore,
			nonceStore,
			clock.RealClock{},
			clock.UUIDGenerator{},
		),
	}
}

// Handle processes authorization HTTP requests
func (h *Handler) Handle(c *gin.Context) {
	httpReq := NewRequest(c)

	// Convert HTTP request to domain request
	domainReq := &authorize.AuthorizeRequest{
		ClientID:            httpReq.ClientID,
		RedirectURI:         httpReq.RedirectURI,
		ResponseType:        httpReq.ResponseType,
		Scope:               httpReq.Scope,
		State:               httpReq.State,
		Nonce:               httpReq.Nonce,
		CodeChallenge:       httpReq.CodeChallenge,
		CodeChallengeMethod: httpReq.CodeChallengeMethod,
		UserID:              c.GetHeader("X-Authenticated-User"),
	}

	result, errType, err := h.service.Authorize(c.Request.Context(), domainReq)
	if err != nil {
		// System error
		HandleSystemError(c, err, httpReq)
		return
	}

	if errType != 0 { // ErrorType enum starts from 0, so non-zero means error
		// Domain error
		HandleDomainError(c, errType, httpReq)
		return
	}

	// Success
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Redirect(http.StatusFound, result.RedirectURL)
}
