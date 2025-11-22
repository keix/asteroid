package data

import (
	"context"
	"os"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"gopkg.in/yaml.v3"
)

// ClientData represents the structure of clients.yaml
type ClientData struct {
	Clients []entity.Client `yaml:"clients"`
}

// ClientLoader handles loading clients from YAML files
type ClientLoader struct {
	filepath string
}

// NewClientLoader creates a new client loader
func NewClientLoader(filepath string) *ClientLoader {
	return &ClientLoader{
		filepath: filepath,
	}
}

// Load reads clients from YAML file and saves to store
func (l *ClientLoader) Load(ctx context.Context, stores *store.Stores) error {
	data, err := os.ReadFile(l.filepath)
	if err != nil {
		return err
	}

	var clientData ClientData
	if err := yaml.Unmarshal(data, &clientData); err != nil {
		return err
	}

	// Type assert to access SaveClient method
	if clientStore, ok := stores.Client.(interface {
		SaveClient(context.Context, *entity.Client) error
	}); ok {
		for i := range clientData.Clients {
			client := &clientData.Clients[i]
			if err := clientStore.SaveClient(ctx, client); err != nil {
				return err
			}
		}
	}

	return nil
}
