package data

import (
	"context"

	"asteroid/internal/store"
)

// Loader coordinates loading of all data types
type Loader struct {
	clientLoader *ClientLoader
}

// NewLoader creates a new data loader with specified file paths
func NewLoader(dataDir string) *Loader {
	return &Loader{
		clientLoader: NewClientLoader(dataDir + "/clients.yaml"),
	}
}

// LoadAll loads all seed data into stores
func (l *Loader) LoadAll(ctx context.Context, stores *store.Stores) error {
	// Load clients
	if err := l.clientLoader.Load(ctx, stores); err != nil {
		return err
	}

	return nil
}
