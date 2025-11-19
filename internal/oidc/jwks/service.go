package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"asteroid/internal/store"
)

// Service handles JWKS business logic
type Service struct {
	keyStore store.KeyStore
}

// NewService creates a new JWKS service
func NewService(keyStore store.KeyStore) *Service {
	return &Service{
		keyStore: keyStore,
	}
}

// GetJWKSet retrieves the JSON Web Key Set (pure business logic)
func (s *Service) GetJWKSet(ctx context.Context) (*JWKSet, error) {
	// Get signing key
	privateKey, err := s.keyStore.GetSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	// Get key ID
	kid, err := s.keyStore.GetKid(ctx)
	if err != nil {
		return nil, err
	}

	// Convert RSA public key to JWK
	jwk := s.rsaToJWK(privateKey, kid)

	return &JWKSet{
		Keys: []JWK{jwk},
	}, nil
}

// rsaToJWK converts RSA private key to JWK format
func (s *Service) rsaToJWK(privateKey *rsa.PrivateKey, kid string) JWK {
	pub := &privateKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   n,
		E:   e,
	}
}