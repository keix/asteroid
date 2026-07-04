package entity

// Client represents an OAuth 2.0 client entity
type Client struct {
	ID                      string   `json:"id" yaml:"id"`
	Secret                  string   `json:"secret" yaml:"secret"`
	RedirectURIs            []string `json:"redirect_uris" yaml:"redirect_uris"`
	Name                    string   `json:"name" yaml:"name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" yaml:"token_endpoint_auth_method"`
	ClientType              string   `json:"client_type" yaml:"client_type"` // "confidential" or "public"

	// Grant / scope / audience policy enforced at the token endpoint.
	// Empty AllowedGrantTypes defaults to ["authorization_code", "refresh_token"] for backward compatibility.
	AllowedGrantTypes []string `json:"allowed_grant_types" yaml:"allowed_grant_types"`
	AllowedScopes     []string `json:"allowed_scopes" yaml:"allowed_scopes"`
	AllowedAudiences  []string `json:"allowed_audiences" yaml:"allowed_audiences"`
}

// IsPublicClient returns true if this is a public client (no client secret authentication)
func (c *Client) IsPublicClient() bool {
	return c.ClientType == "public"
}

// IsConfidentialClient returns true if this is a confidential client (has client secret)
func (c *Client) IsConfidentialClient() bool {
	return c.ClientType == "confidential" || c.ClientType == "" // default to confidential for backward compatibility
}

// EffectiveGrantTypes returns the client's allowed grant types with the
// backward-compatible default applied when AllowedGrantTypes is empty.
func (c *Client) EffectiveGrantTypes() []string {
	if len(c.AllowedGrantTypes) == 0 {
		return []string{"authorization_code", "refresh_token"}
	}
	return c.AllowedGrantTypes
}

// IsGrantTypeAllowed reports whether the given grant type is permitted for this client.
func (c *Client) IsGrantTypeAllowed(grantType string) bool {
	for _, gt := range c.EffectiveGrantTypes() {
		if gt == grantType {
			return true
		}
	}
	return false
}
