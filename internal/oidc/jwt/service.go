package jwt

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"asteroid/internal/store"
)

// Service handles JWT ID Token generation
type Service struct {
	keyStore store.KeyStore
	issuer   string
}

// NewService creates a new JWT service
func NewService(keyStore store.KeyStore, issuer string) *Service {
	return &Service{
		keyStore: keyStore,
		issuer:   issuer,
	}
}

// GenerateIDToken creates a signed JWT ID Token
func (s *Service) GenerateIDToken(ctx context.Context, userID, clientID, nonce string) (string, error) {
	now := time.Now()

	claims := &IDTokenClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  clientID,
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		AuthTime:  now.Unix(), // Simplified: auth time = issued time
		Nonce:     nonce,
	}

	// Get signing key and kid
	privateKey, err := s.keyStore.GetSigningKey(ctx)
	if err != nil {
		return "", err
	}

	kid, err := s.keyStore.GetKid(ctx)
	if err != nil {
		return "", err
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	// Sign the token
	return token.SignedString(privateKey)
}

// Custom claims implementation for jwt library compatibility
func (c *IDTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

func (c *IDTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

func (c *IDTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c *IDTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c *IDTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c *IDTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}
