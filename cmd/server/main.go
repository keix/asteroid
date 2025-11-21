package main

import (
	"context"
	"log"

	"asteroid/internal/config"
	"asteroid/internal/http"
	"asteroid/internal/store"
	"asteroid/internal/store/dynamodb"
	"asteroid/internal/store/entity"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	stores, err := dynamodb.NewStores(&cfg)
	if err != nil {
		log.Fatalf("failed to initialize stores: %v", err)
	}

	err = setupTestData(stores)
	if err != nil {
		log.Fatalf("failed to setup test data: %v", err)
	}

	r := gin.Default()
	http.RegisterRoutes(r, stores.Key, stores.User, stores.Client, stores.AuthCode, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}

func setupTestData(stores *store.Stores) error {
	testUser := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}

	// Type assert to access SaveUser method
	if userStore, ok := stores.User.(interface {
		SaveUser(context.Context, *entity.User) error
	}); ok {
		if err := userStore.SaveUser(context.Background(), testUser); err != nil {
			return err
		}
	}

	testClient := &entity.Client{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Name:         "Test Client",
	}

	// Type assert to access SaveClient method
	if clientStore, ok := stores.Client.(interface {
		SaveClient(context.Context, *entity.Client) error
	}); ok {
		if err := clientStore.SaveClient(context.Background(), testClient); err != nil {
			return err
		}
	}

	return nil
}
