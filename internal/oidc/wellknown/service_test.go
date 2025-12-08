package wellknown

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWellKnownConfiguration(t *testing.T) {
	issuer := "https://auth.example.com"
	service := NewService(issuer)

	config := service.GetOpenIDConfiguration()

	// issuer should be correct
	assert.Equal(t, issuer, config.Issuer)

	// endpoints should be correct
	assert.Equal(t, issuer+"/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, issuer+"/token", config.TokenEndpoint)

	// jwks_uri should be correct
	assert.Equal(t, issuer+"/jwks.json", config.JwksURI)

	// scopes_supported should be correct
	assert.Contains(t, config.ScopesSupported, "openid")

	// response_types_supported should be correct
	assert.Contains(t, config.ResponseTypesSupported, "code")
}
