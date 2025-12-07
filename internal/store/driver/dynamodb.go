//go:build dynamodb
// +build dynamodb

package driver

import (
	"asteroid/internal/config"
	"asteroid/internal/store"
	"asteroid/internal/store/dynamodb"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	return dynamodb.NewStores(cfg)
}
