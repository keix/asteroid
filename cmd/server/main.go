package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"asteroid/internal/config"
	"asteroid/internal/http"
	"asteroid/internal/key"
)

func main() {
	cfg := config.Load()

	provider, err := key.NewLocalKeyProvider(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	r := gin.Default()
	http.RegisterRoutes(r, provider, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}