//go:build memory || !redis

package driver

import (
	"asteroid/internal/clock"
	"asteroid/internal/config"
	"asteroid/internal/store"
	"asteroid/internal/store/memory"
)

func NewStores(cfg *config.Config, clk clock.Clock) (*store.Stores, error) {
	return memory.NewStores(cfg, clk)
}
