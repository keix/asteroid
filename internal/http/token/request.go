package token

import (
	"net/url"

	"github.com/gin-gonic/gin"
)

// Request represents an OAuth 2.0 token request
type Request struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	Scope        string `json:"scope" form:"scope"`
	Audience     string `json:"audience" form:"audience"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	AuthMethod   string // client_secret_post or client_secret_basic
}

// NewRequest creates Request from gin.Context
// Supports both client_secret_post (form) and client_secret_basic (HTTP Basic) authentication
func NewRequest(c *gin.Context) *Request {
	var req Request

	// Try to bind as form data first
	c.ShouldBind(&req)

	// Fallback to query parameters for any missing fields
	if req.GrantType == "" {
		req.GrantType = c.PostForm("grant_type")
	}
	if req.Code == "" {
		req.Code = c.PostForm("code")
	}
	if req.RedirectURI == "" {
		req.RedirectURI = c.PostForm("redirect_uri")
	}
	if req.RefreshToken == "" {
		req.RefreshToken = c.PostForm("refresh_token")
	}
	if req.Scope == "" {
		req.Scope = c.PostForm("scope")
	}
	if req.Audience == "" {
		req.Audience = c.PostForm("audience")
	}
	if req.CodeVerifier == "" {
		req.CodeVerifier = c.PostForm("code_verifier")
	}

	// Handle client authentication - HTTP Basic takes precedence
	if clientID, clientSecret, ok := c.Request.BasicAuth(); ok {
		// client_secret_basic (HTTP Basic Auth)
		// RFC 6749 requires both values to be form-url-encoded before
		// constructing the Basic credentials.
		if decoded, err := url.QueryUnescape(clientID); err == nil {
			req.ClientID = decoded
		} else {
			req.ClientID = clientID
		}
		if decoded, err := url.QueryUnescape(clientSecret); err == nil {
			req.ClientSecret = decoded
		} else {
			req.ClientSecret = clientSecret
		}
		req.AuthMethod = "client_secret_basic"
	} else if req.ClientID != "" || req.ClientSecret != "" {
		// client_secret_post (form parameters)
		req.AuthMethod = "client_secret_post"
		// ClientID and ClientSecret already set from form binding
	} else {
		// Fallback: check form parameters explicitly
		if formClientID := c.PostForm("client_id"); formClientID != "" {
			req.ClientID = formClientID
			req.ClientSecret = c.PostForm("client_secret")
			req.AuthMethod = "client_secret_post"
		}
	}

	return &req
}
