package dynamodb

import (
	"context"

	"asteroid/internal/config"
	"asteroid/internal/store"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func NewStores(cfg *config.Config) (*store.Stores, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(cfg.DynamoDBRegion),
	)
	if err != nil {
		return nil, err
	}

	client := dynamodb.NewFromConfig(awsCfg)

	return &store.Stores{
		Key:      NewKeyStore(client, cfg.DynamoDBKeysTable, cfg.DynamoDBKeyID),
		User:     NewUserStore(client, cfg.DynamoDBUsersTable),
		Client:   NewClientStore(client, cfg.DynamoDBClientsTable),
		AuthCode: NewAuthCodeStore(client, cfg.DynamoDBAuthCodeTable),
	}, nil
}
