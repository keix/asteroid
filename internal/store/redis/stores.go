package redis

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
	"github.com/redis/go-redis/v9"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	// Key, User, Client stores use file-based memory implementation
	keyStore, err := NewKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	// AuthCode store uses Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	return &store.Stores{
		Key:      keyStore,
		User:     NewUserStore(),
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(redisClient),
		Token:    NewTokenStore(redisClient),
	}, nil
}
