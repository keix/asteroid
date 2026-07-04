package token

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"asteroid/internal/clock"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store/entity"
)

const (
	ccIssuer  = "https://auth.example.test"
	ccJTI     = "test-jti-abc"
	ccClient  = "svc-client"
	ccSecret  = "svc-secret"
	ccAud1    = "api.example.test"
	ccAud2    = "reports.example.test"
	ccScope1  = "widgets:read"
	ccScope2  = "widgets:write"
	ccBadScop = "not:allowed"
)

var ccFixedTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func newClientCredentialsService(t *testing.T, client *entity.Client) *Service {
	t.Helper()
	clk := clock.FixedClock{Time: ccFixedTime}
	gen := &clock.FixedGenerator{Token: ccJTI}
	sig := signing.NewFileService(context.Background(), t.TempDir(), 15*time.Minute, 1*time.Hour, clk)
	t.Cleanup(func() { sig.Close() })

	return NewService(
		&MockAuthCodeStore{},
		&MockTokenStore{},
		&MockClientStore{clients: map[string]*entity.Client{client.ID: client}},
		sig,
		&MockUserinfoProvider{},
		ccIssuer,
		clk,
		gen,
	)
}

func TestClientCredentials_HappyPath_MintsRFC9068JWT(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1, ccScope2},
		AllowedAudiences:  []string{ccAud1},
	})

	res, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
		Scope:        ccScope1,
	})

	require.NoError(t, err)
	require.Equal(t, ErrorNone, errType)
	require.NotNil(t, res)
	assert.Equal(t, "Bearer", res.TokenType)
	assert.Equal(t, 3600, res.ExpiresIn)
	assert.Equal(t, ccScope1, res.Scope)
	assert.Empty(t, res.RefreshToken, "client_credentials must not return a refresh token")
	assert.Empty(t, res.IDToken, "client_credentials must not return an id token")

	claims := decodeClaims(t, svc, res.AccessToken)
	assert.Equal(t, ccIssuer, claims["iss"])
	assert.Equal(t, ccClient, claims["sub"])
	assert.Equal(t, ccClient, claims["client_id"])
	assert.Equal(t, ccAud1, claims["aud"])
	assert.Equal(t, "access", claims["token_use"])
	assert.Equal(t, ccScope1, claims["scope"])
	assert.Equal(t, ccJTI, claims["jti"])
	assert.EqualValues(t, ccFixedTime.Unix(), int64(claims["iat"].(float64)))
	assert.EqualValues(t, ccFixedTime.Add(1*time.Hour).Unix(), int64(claims["exp"].(float64)))
}

func TestClientCredentials_DefaultsScopeToAllowedList(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1, ccScope2},
		AllowedAudiences:  []string{ccAud1},
	})

	res, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	require.Equal(t, ErrorNone, errType)
	assert.Equal(t, ccScope1+" "+ccScope2, res.Scope)
}

func TestClientCredentials_DefaultsAudienceWhenSingleAllowed(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	res, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	require.Equal(t, ErrorNone, errType)
	claims := decodeClaims(t, svc, res.AccessToken)
	assert.Equal(t, ccAud1, claims["aud"])
}

func TestClientCredentials_MultipleAudiencesRequireExplicit(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1, ccAud2},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidRequest, errType)
}

func TestClientCredentials_UnknownAudience_ReturnsInvalidTarget(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
		Audience:     "unregistered.example.test",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidTarget, errType)
}

func TestClientCredentials_UnknownScope_ReturnsInvalidScope(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
		Scope:        ccBadScop,
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidScope, errType)
}

func TestClientCredentials_PublicClient_Rejected(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		ClientType:        "public",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:  "client_credentials",
		ClientID:   ccClient,
		AuthMethod: "client_secret_post",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidClient, errType)
}

func TestClientCredentials_GrantNotAllowed_ReturnsUnauthorizedClient(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"authorization_code"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorUnauthorizedClient, errType)
}

func TestClientCredentials_NoAudiencesConfigured_ReturnsInvalidRequest(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		// AllowedAudiences intentionally empty
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: ccSecret,
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidRequest, errType)
}

func TestClientCredentials_WrongSecret_ReturnsInvalidClient(t *testing.T) {
	svc := newClientCredentialsService(t, &entity.Client{
		ID:                ccClient,
		Secret:            ccSecret,
		ClientType:        "confidential",
		AllowedGrantTypes: []string{"client_credentials"},
		AllowedScopes:     []string{ccScope1},
		AllowedAudiences:  []string{ccAud1},
	})

	_, errType, err := svc.ExchangeToken(context.Background(), &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     ccClient,
		ClientSecret: "wrong",
		AuthMethod:   "client_secret_post",
	})

	require.NoError(t, err)
	assert.Equal(t, ErrorInvalidClient, errType)
}

// decodeClaims parses the JWT and verifies its signature against the active key.
func decodeClaims(t *testing.T, svc *Service, token string) jwt.MapClaims {
	t.Helper()
	key, err := svc.SigningService.GetActiveKey("ES256")
	require.NoError(t, err)

	parsed, err := jwt.Parse(
		token,
		func(_ *jwt.Token) (interface{}, error) { return key.PublicKey, nil },
		jwt.WithTimeFunc(func() time.Time { return ccFixedTime }),
	)
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}
