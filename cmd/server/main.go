package main

import (
	"log"

	"asteroid/internal/config"
	"asteroid/internal/http"
	"asteroid/internal/store"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	keyStore, err := store.NewLocalKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	userStore := store.NewMemoryUserStore()
	clientStore := store.NewMemoryClientStore()
	authCodeStore := store.NewMemoryAuthCodeStore()

	setupTestData(userStore, clientStore)

	r := gin.Default()
	http.RegisterRoutes(r, keyStore, userStore, clientStore, authCodeStore, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}

func setupTestData(userStore *store.MemoryUserStore, clientStore *store.MemoryClientStore) {
	testUser := &store.User{
		ID:    "user-123",
		Email: "test@example.com",
	}
	userStore.SaveUser(testUser)

	testClient := &store.Client{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Name:         "Test Client",
	}
	clientStore.SaveClient(testClient)
}
