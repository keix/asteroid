package main

import (
	"log"

	"asteroid/internal/config"
	"asteroid/internal/http"
	"asteroid/internal/store/entity"
	"asteroid/internal/store/memory"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	keyStore, err := memory.NewKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	userStore := memory.NewUserStore()
	clientStore := memory.NewClientStore()
	authCodeStore := memory.NewAuthCodeStore()

	setupTestData(userStore, clientStore)

	r := gin.Default()
	http.RegisterRoutes(r, keyStore, userStore, clientStore, authCodeStore, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}

func setupTestData(userStore *memory.UserStore, clientStore *memory.ClientStore) {
	testUser := &entity.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	userStore.SaveUser(testUser)

	testClient := &entity.Client{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Name:         "Test Client",
	}
	clientStore.SaveClient(testClient)
}
