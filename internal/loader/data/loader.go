package data

import (
	"context"

	"asteroid/internal/store"
)

// Loader coordinates loading of all data types
type Loader struct {
	userLoader   *UserLoader
	clientLoader *ClientLoader
}

// NewLoader creates a new data loader with specified file paths
func NewLoader(dataDir string) *Loader {
	return &Loader{
		userLoader:   NewUserLoader(dataDir + "/users.yaml"),
		clientLoader: NewClientLoader(dataDir + "/clients.yaml"),
	}
}

// LoadAll loads all seed data into stores
func (l *Loader) LoadAll(ctx context.Context, stores *store.Stores) error {
	// Load users
	if err := l.userLoader.Load(ctx, stores); err != nil {
		return err
	}

	// Load clients
	if err := l.clientLoader.Load(ctx, stores); err != nil {
		return err
	}

	return nil
}
