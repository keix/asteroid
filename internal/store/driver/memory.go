//go:build memory || !redis

package driver

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
	"asteroid/internal/store/memory"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	return memory.NewStores(cfg)
}
