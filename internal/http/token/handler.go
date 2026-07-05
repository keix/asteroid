package token

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"asteroid/internal/clock"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/oidc/token"
	"asteroid/internal/store"
	"asteroid/internal/userinfo"
)

// Handler handles HTTP requests for token endpoint
type Handler struct {
	service *token.Service
}

// NewHandler creates a new token handler
func NewHandler(
	issuer string,
	clientStore store.ClientStore,
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	userinfoProvider userinfo.Provider,
	signingService *signing.Service,
) *Handler {
	return &Handler{
		service: token.NewService(
			authCodeStore,
			tokenStore,
			clientStore,
			signingService,
			userinfoProvider,
			issuer,
			clock.RealClock{},
			clock.UUIDGenerator{},
		),
	}
}

// Handle processes token HTTP requests
func (h *Handler) Handle(c *gin.Context) {
	httpReq := NewRequest(c)

	// Convert HTTP request to domain request
	domainReq := &token.TokenRequest{
		GrantType:    httpReq.GrantType,
		Code:         httpReq.Code,
		RedirectURI:  httpReq.RedirectURI,
		ClientID:     httpReq.ClientID,
		ClientSecret: httpReq.ClientSecret,
		RefreshToken: httpReq.RefreshToken,
		Scope:        httpReq.Scope,
		Audience:     httpReq.Audience,
		CodeVerifier: httpReq.CodeVerifier,
		AuthMethod:   httpReq.AuthMethod,
	}

	result, errType, err := h.service.ExchangeToken(c.Request.Context(), domainReq)
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

	// Success - convert domain result to HTTP response
	response := &Response{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		Scope:        result.Scope,
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, response)
}
