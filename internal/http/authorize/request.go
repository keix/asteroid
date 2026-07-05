package authorize

import "github.com/gin-gonic/gin"

// Request represents an OAuth 2.0 authorization request
type Request struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// NewRequest creates Request from gin.Context
func NewRequest(c *gin.Context) *Request {
	_ = c.Request.ParseForm()
	form := c.Request.Form

	return &Request{
		ClientID:            form.Get("client_id"),
		RedirectURI:         form.Get("redirect_uri"),
		ResponseType:        form.Get("response_type"),
		Scope:               form.Get("scope"),
		State:               form.Get("state"),
		Nonce:               form.Get("nonce"),
		CodeChallenge:       form.Get("code_challenge"),
		CodeChallengeMethod: form.Get("code_challenge_method"),
	}
}
