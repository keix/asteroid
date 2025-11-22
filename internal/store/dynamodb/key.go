package dynamodb

import (
	"context"
	"crypto/rsa"

	"asteroid/internal/loader/key"
)

type KeyStore struct {
	privateKey *rsa.PrivateKey
	kid        string
}

func NewKeyStore(path string) (*KeyStore, error) {
	privateKey, kid, err := key.LoadRSAKey(key.LoaderTypeFile, path)
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		privateKey: privateKey,
		kid:        kid,
	}, nil
}

func (s *KeyStore) GetSigningKey(ctx context.Context) (*rsa.PrivateKey, error) {
	return s.privateKey, nil
}

func (s *KeyStore) GetKid(ctx context.Context) (string, error) {
	return s.kid, nil
}
