package redis

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
	"github.com/redis/go-redis/v9"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	// Redis client for distributed stores
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	return &store.Stores{
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(redisClient),
		Token:    NewTokenStore(redisClient),
		Nonce:    NewNonceStore(redisClient),
		// Key and JWT stores removed - using signing.Service instead
	}, nil
}
