package main

import (
	"context"
	"log"
	"time"

	"asteroid/internal/config"
	"asteroid/internal/http"
	"asteroid/internal/loader/data"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store"
	"asteroid/internal/store/driver"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	cfg := config.Load()

	stores, err := driver.NewStores(&cfg)
	if err != nil {
		log.Fatalf("failed to initialize stores: %v", err)
	}

	err = setupSeedData(stores)
	if err != nil {
		log.Fatalf("failed to setup seed data: %v", err)
	}

	// Initialize signing service for automatic key rotation
	signingService := signing.NewFileService(
		context.Background(),
		"./keys",      // Key storage directory
		1*time.Minute, // ID token TTL (testing: 1 minute)
		1*time.Minute, // Key rotation interval (testing: 1 minute)
	)
	defer signingService.Close()

	// Minimal Gin engine
	r := gin.New()
	r.Use(gin.Recovery()) // keep system reliable, but silent
	r.SetTrustedProxies(nil)

	http.RegisterRoutes(r, stores, signingService, cfg)

	// Development: HTTP server on port 8880
	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")

	// Production: Unix socket (uncomment for production deployment)
	// Note: Clean up socket file on shutdown with signal handlers
	// log.Println("Asteroid OIDC Provider running on unix:/var/run/asteroid/asteroid.sock")
	// r.RunUnix("/var/run/asteroid/asteroid.sock")
}

func setupSeedData(stores *store.Stores) error {
	loader := data.NewLoader("./data")
	return loader.LoadAll(context.Background(), stores)
}
