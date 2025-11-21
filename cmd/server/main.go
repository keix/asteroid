package main

import (
	"context"
	"log"

	"asteroid/internal/config"
	"asteroid/internal/http"
	dynamodbstore "asteroid/internal/store/dynamodb"
	"asteroid/internal/store/entity"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	// Initialize AWS config
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(cfg.DynamoDBRegion),
	)
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}

	// Create DynamoDB client
	dynamoClient := dynamodb.NewFromConfig(awsCfg)

	keyStore := dynamodbstore.NewKeyStore(dynamoClient, cfg.DynamoDBKeysTable, cfg.DynamoDBKeyID)
	userStore := dynamodbstore.NewUserStore(dynamoClient, cfg.DynamoDBUsersTable)
	clientStore := dynamodbstore.NewClientStore(dynamoClient, cfg.DynamoDBClientsTable)
	authCodeStore := dynamodbstore.NewAuthCodeStore(dynamoClient, cfg.DynamoDBAuthCodeTable)

	err = setupTestData(userStore, clientStore)
	if err != nil {
		log.Fatalf("failed to setup test data: %v", err)
	}

	r := gin.Default()
	http.RegisterRoutes(r, keyStore, userStore, clientStore, authCodeStore, cfg)

	log.Println("Asteroid OIDC Provider running on :8880")
	r.Run(":8880")
}

func setupTestData(userStore *dynamodbstore.UserStore, clientStore *dynamodbstore.ClientStore) error {
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

	return nil
}
