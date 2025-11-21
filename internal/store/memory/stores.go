package memory

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	keyStore, err := NewKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	return &store.Stores{
		Key:      keyStore,
		User:     NewUserStore(),
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(),
		Token:    NewTokenStore(),
	}, nil
}
