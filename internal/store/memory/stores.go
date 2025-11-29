package memory

import (
	"context"

	"asteroid/internal/config"
	"asteroid/internal/store"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	return NewStoresWithContext(context.Background(), cfg)
}

func NewStoresWithContext(ctx context.Context, cfg *config.Config) (*store.Stores, error) {
	// KeyStore and JWTStore removed - using signing.Manager instead
	return &store.Stores{
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(),
		Token:    NewTokenStore(ctx),
		Nonce:    NewNonceStore(ctx),
		// Key and JWT fields removed from stores
	}, nil
}
