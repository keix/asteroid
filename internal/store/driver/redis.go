//go:build redis

package driver

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
	"asteroid/internal/store/redis"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	return redis.NewStores(cfg)
}
