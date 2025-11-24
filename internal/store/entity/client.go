package entity

// Client represents an OAuth 2.0 client entity
type Client struct {
	ID                      string   `json:"id" yaml:"id"`
	Secret                  string   `json:"secret" yaml:"secret"`
	RedirectURIs            []string `json:"redirect_uris" yaml:"redirect_uris"`
	Name                    string   `json:"name" yaml:"name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" yaml:"token_endpoint_auth_method"`
	ClientType              string   `json:"client_type" yaml:"client_type"` // "confidential" or "public"
}

// IsPublicClient returns true if this is a public client (no client secret authentication)
func (c *Client) IsPublicClient() bool {
	return c.ClientType == "public"
}

// IsConfidentialClient returns true if this is a confidential client (has client secret)
func (c *Client) IsConfidentialClient() bool {
	return c.ClientType == "confidential" || c.ClientType == "" // default to confidential for backward compatibility
}
