package data

import (
	"context"
	"os"
	"time"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"gopkg.in/yaml.v3"
)

type UserData struct {
	Users []entity.User `yaml:"users"`
}

type ClientData struct {
	Clients []entity.Client `yaml:"clients"`
}

func LoadSeedData(ctx context.Context, stores *store.Stores, dataDir string) error {
	// Load users
	if err := loadUsers(ctx, stores, dataDir+"/users.yaml"); err != nil {
		return err
	}

	// Load clients
	if err := loadClients(ctx, stores, dataDir+"/clients.yaml"); err != nil {
		return err
	}

	return nil
}

func loadUsers(ctx context.Context, stores *store.Stores, filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	var userData UserData
	if err := yaml.Unmarshal(data, &userData); err != nil {
		return err
	}

	// Type assert to access SaveUser method
	if userStore, ok := stores.User.(interface {
		SaveUser(context.Context, *entity.User) error
	}); ok {
		for i := range userData.Users {
			user := &userData.Users[i]
			// Parse created_at if it's a string
			if user.CreatedAt.IsZero() {
				user.CreatedAt = time.Now()
			}
			if err := userStore.SaveUser(ctx, user); err != nil {
				return err
			}
		}
	}

	return nil
}

func loadClients(ctx context.Context, stores *store.Stores, filepath string) error {
	data, err := os.ReadFile(filepath)
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
