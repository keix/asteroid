package wellknown

// Service handles OpenID Connect Discovery business logic
type Service struct {
	issuer string
}

// NewService creates a new Well-known service
func NewService(issuer string) *Service {
	return &Service{
		issuer: issuer,
	}
}

// GetOpenIDConfiguration returns the OpenID Connect Discovery document (pure business logic)
func (s *Service) GetOpenIDConfiguration() *OpenIDConfiguration {
	return &OpenIDConfiguration{
		Issuer:                            s.issuer,
		AuthorizationEndpoint:             s.issuer + "/authorize",
		TokenEndpoint:                     s.issuer + "/token",
		JwksURI:                           s.issuer + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ResponseModesSupported:            []string{"query"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "nonce"},
	}
}
