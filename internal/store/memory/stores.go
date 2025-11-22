package memory

import (
	"context"

	"asteroid/internal/config"
	"asteroid/internal/oidc/jwt"
	"asteroid/internal/store"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	return NewStoresWithContext(context.Background(), cfg)
}

func NewStoresWithContext(ctx context.Context, cfg *config.Config) (*store.Stores, error) {
	keyStore, err := NewKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	jwtStore := jwt.NewService(keyStore, cfg.Issuer)

	return &store.Stores{
		Key:      keyStore,
		User:     NewUserStore(),
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(),
		Token:    NewTokenStore(ctx),
		JWT:      jwtStore,
		Nonce:    NewNonceStore(ctx),
	}, nil
}
