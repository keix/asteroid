package authorize

import "github.com/gin-gonic/gin"

// Request represents an OAuth 2.0 authorization request
type Request struct {
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
}

// NewRequest creates Request from gin.Context
func NewRequest(c *gin.Context) *Request {
	return &Request{
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		ResponseType: c.Query("response_type"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),
	}
}
