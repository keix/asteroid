package entity

// Client represents an OAuth 2.0 client entity
type Client struct {
	ID                      string   `json:"id" yaml:"id"`
	Secret                  string   `json:"secret" yaml:"secret"`
	RedirectURIs            []string `json:"redirect_uris" yaml:"redirect_uris"`
	Name                    string   `json:"name" yaml:"name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" yaml:"token_endpoint_auth_method"`
}
