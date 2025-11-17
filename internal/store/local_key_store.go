package store

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type LocalKeyStore struct {
	privateKey *rsa.PrivateKey
	kid        string
}

func NewLocalKeyStore(path string) (KeyStore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	priv, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return nil, err
	}

	kid := generateKID(priv.PublicKey)

	return &LocalKeyStore{
		privateKey: priv,
		kid:        kid,
	}, nil
}

func (s *LocalKeyStore) GetSigningKey(ctx context.Context) (*rsa.PrivateKey, error) {
	return s.privateKey, nil
}

func (s *LocalKeyStore) GetKid(ctx context.Context) (string, error) {
	return s.kid, nil
}

func generateKID(pub rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	sum := sha256.Sum256([]byte(n + e))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
