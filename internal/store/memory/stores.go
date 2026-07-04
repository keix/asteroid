package memory

import (
	"context"

	"asteroid/internal/clock"
	"asteroid/internal/config"
	"asteroid/internal/store"
)

func NewStores(cfg *config.Config, clk clock.Clock) (*store.Stores, error) {
	return NewStoresWithContext(context.Background(), cfg, clk)
}

func NewStoresWithContext(ctx context.Context, cfg *config.Config, clk clock.Clock) (*store.Stores, error) {
	// KeyStore and JWTStore removed - using signing.Manager instead
	return &store.Stores{
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(ctx, clk),
		Token:    NewTokenStore(ctx, clk),
		Nonce:    NewNonceStore(ctx, clk),
		// Key and JWT fields removed from stores
	}, nil
}
