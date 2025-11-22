package dynamodb

import (
	"context"

	"asteroid/internal/config"
	"asteroid/internal/oidc/jwt"
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

	keyStore, err := NewKeyStore(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	jwtStore := jwt.NewService(keyStore, cfg.Issuer)

	return &store.Stores{
		Key:      keyStore,
		User:     NewUserStore(),
		Client:   NewClientStore(),
		AuthCode: NewAuthCodeStore(client, cfg.DynamoDBAuthCodeTable),
		Token:    NewTokenStore(client, cfg.DynamoDBAccessTokenTable, cfg.DynamoDBRefreshTokenTable),
		JWT:      jwtStore,
		Nonce:    NewNonceStore(client, cfg.DynamoDBNonceTable),
	}, nil
}
