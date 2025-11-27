package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"asteroid/internal/crypto"
)

// SigningKeyProvider interface for getting keys for JWKS
type SigningKeyProvider interface {
	GetJWKSKeys() []*crypto.KeyPair
}

// Service handles JWKS business logic
type Service struct {
	signingProvider SigningKeyProvider
}

// NewService creates a new JWKS service
func NewService(signingProvider SigningKeyProvider) *Service {
	return &Service{
		signingProvider: signingProvider,
	}
}

// GetJWKSet retrieves the JSON Web Key Set (pure business logic)
func (s *Service) GetJWKSet(ctx context.Context) (*JWKS, error) {
	// Get all valid keys for JWKS
	keyPairs := s.signingProvider.GetJWKSKeys()

	var jwks []JWK
	for _, keyPair := range keyPairs {
		jwk, err := s.keyPairToJWK(keyPair)
		if err != nil {
			// Skip invalid keys but continue
			continue
		}
		jwks = append(jwks, jwk)
	}

	return &JWKS{
		Keys: jwks,
	}, nil
}

// keyPairToJWK converts crypto.KeyPair to JWK format
func (s *Service) keyPairToJWK(keyPair *crypto.KeyPair) (JWK, error) {
	switch keyPair.Algorithm {
	case "RS256", "PS256":
		return s.rsaToJWK(keyPair)
	case "ES256":
		return s.ecdsaToJWK(keyPair)
	default:
		return JWK{}, fmt.Errorf("unsupported algorithm: %s", keyPair.Algorithm)
	}
}

// rsaToJWK converts RSA KeyPair to JWK format
func (s *Service) rsaToJWK(keyPair *crypto.KeyPair) (JWK, error) {
	publicKey, ok := keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("invalid RSA public key")
	}

	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: keyPair.Algorithm,
		Kid: keyPair.KeyID,
		N:   n,
		E:   e,
	}, nil
}

// ecdsaToJWK converts ECDSA KeyPair to JWK format
func (s *Service) ecdsaToJWK(keyPair *crypto.KeyPair) (JWK, error) {
	publicKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return JWK{}, fmt.Errorf("invalid ECDSA public key")
	}

	x := base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes())

	return JWK{
		Kty: "EC",
		Use: "sig",
		Alg: keyPair.Algorithm,
		Kid: keyPair.KeyID,
		Crv: "P-256",
		X:   x,
		Y:   y,
	}, nil
}
