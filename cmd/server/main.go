package main

import (
	"context"
	"log"

	"asteroid/internal/config"
	"asteroid/internal/data"
	"asteroid/internal/http"
	"asteroid/internal/store"
	"asteroid/internal/store/driver"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	stores, err := driver.NewStores(&cfg)
	if err != nil {
		log.Fatalf("failed to initialize stores: %v", err)
	}

	err = setupSeedData(stores)
	if err != nil {
		log.Fatalf("failed to setup seed data: %v", err)
	}

	r := gin.Default()
	http.RegisterRoutes(r, stores.Key, stores.User, stores.Client, stores.AuthCode, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}

func setupSeedData(stores *store.Stores) error {
	return data.LoadSeedData(context.Background(), stores, "./data")
}
