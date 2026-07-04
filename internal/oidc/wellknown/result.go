package wellknown

// OpenIDConfiguration represents the OpenID Connect Discovery document
type OpenIDConfiguration struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                                string   `json:"jwks_uri"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                    []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	AccessTokenSigningAlgValuesSupported   []string `json:"access_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                        []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                        []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported,omitempty"`
}
