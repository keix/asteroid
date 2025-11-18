package oidc

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"asteroid/internal/store"
)

type AuthorizeHandler struct {
	ClientStore   store.ClientStore
	UserStore     store.UserStore
	AuthCodeStore store.AuthCodeStore
}

func NewAuthorizeHandler(
	clientStore store.ClientStore,
	userStore store.UserStore,
	authCodeStore store.AuthCodeStore,
) *AuthorizeHandler {
	return &AuthorizeHandler{
		ClientStore:   clientStore,
		UserStore:     userStore,
		AuthCodeStore: authCodeStore,
	}
}

func (h *AuthorizeHandler) HandleAuthorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	if clientID == "" || redirectURI == "" || responseType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required parameters"})
		return
	}

	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported response_type"})
		return
	}

	if scope != "openid" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope"})
		return
	}

	client, err := h.ClientStore.GetClient(c.Request.Context(), clientID)
	if err != nil || client == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client"})
		return
	}

	validRedirectURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirectURI = true
			break
		}
	}
	if !validRedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect_uri"})
		return
	}

	user, err := h.UserStore.GetUserByID(c.Request.Context(), "user-123")
	if err != nil || user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}

	code := uuid.NewString()
	authCode := &store.AuthCode{
		Code:        code,
		ClientID:    client.ID,
		UserID:      user.ID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := h.AuthCodeStore.SaveAuthCode(c.Request.Context(), authCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store authorization code"})
		return
	}

	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}

	c.Redirect(http.StatusFound, redirect)
}