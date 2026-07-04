//go:build redis
// +build redis

package driver

import (
	"asteroid/internal/clock"
	"asteroid/internal/config"
	"asteroid/internal/store"
	"asteroid/internal/store/redis"
)

func NewStores(cfg *config.Config, _ clock.Clock) (*store.Stores, error) {
	return redis.NewStores(cfg)
}
