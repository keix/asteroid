package token

import (
	"net/http"

	"github.com/gin-gonic/gin"

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
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	clientStore store.ClientStore,
	signingService *signing.Service,
	userinfoProvider userinfo.Provider,
	issuer string,
) *Handler {
	return &Handler{
		service: token.NewService(authCodeStore, tokenStore, clientStore, signingService, userinfoProvider, issuer),
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
		CodeVerifier: httpReq.CodeVerifier,
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

	c.JSON(http.StatusOK, response)
}
