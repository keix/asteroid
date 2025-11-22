package data

import (
	"context"
	"os"
	"time"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"gopkg.in/yaml.v3"
)

// UserData represents the structure of users.yaml
type UserData struct {
	Users []entity.User `yaml:"users"`
}

// UserLoader handles loading users from YAML files
type UserLoader struct {
	filepath string
}

// NewUserLoader creates a new user loader
func NewUserLoader(filepath string) *UserLoader {
	return &UserLoader{
		filepath: filepath,
	}
}

// Load reads users from YAML file and saves to store
func (l *UserLoader) Load(ctx context.Context, stores *store.Stores) error {
	data, err := os.ReadFile(l.filepath)
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
			// Set created_at if not provided
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
