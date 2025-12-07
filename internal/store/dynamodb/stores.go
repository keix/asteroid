//go:build dynamodb
// +build dynamodb

package dynamodb

import (
	"context"
	"time"

	"asteroid/internal/config"
	"asteroid/internal/store"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	// Create context with timeout for AWS config loading
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.DynamoDBRegion),
		// Remove verbose logging for performance
	)
	if err != nil {
		return nil, err
	}

	// Configure DynamoDB client
	client := dynamodb.NewFromConfig(awsCfg)

	return &store.Stores{
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(client, cfg.DynamoDBAuthCodeTable),
		Token:    NewTokenStore(client, cfg.DynamoDBAccessTokenTable, cfg.DynamoDBRefreshTokenTable),
		Nonce:    NewNonceStore(client, cfg.DynamoDBNonceTable),
		// Key and JWT stores removed - using signing.Service instead
	}, nil
}
