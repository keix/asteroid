package token

import "github.com/gin-gonic/gin"

// Request represents an OAuth 2.0 token request
type Request struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	Scope        string `json:"scope" form:"scope"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
}

// NewRequest creates Request from gin.Context
func NewRequest(c *gin.Context) *Request {
	var req Request

	// Try to bind as form data first (standard OAuth 2.0)
	if err := c.ShouldBind(&req); err == nil {
		return &req
	}

	// Fallback to query parameters
	return &Request{
		GrantType:    c.PostForm("grant_type"),
		Code:         c.PostForm("code"),
		RedirectURI:  c.PostForm("redirect_uri"),
		ClientID:     c.PostForm("client_id"),
		ClientSecret: c.PostForm("client_secret"),
		RefreshToken: c.PostForm("refresh_token"),
		Scope:        c.PostForm("scope"),
		CodeVerifier: c.PostForm("code_verifier"),
	}
}
