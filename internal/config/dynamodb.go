//go:build dynamodb

package config

import "os"

type Config struct {
	Issuer         string
	PrivateKeyPath string

	DynamoDBRegion            string
	DynamoDBAuthCodeTable     string
	DynamoDBAccessTokenTable  string
	DynamoDBRefreshTokenTable string
	DynamoDBNonceTable        string
}

func Load() Config {
	return Config{
		Issuer:         getenv("OIDC_ISSUER", "http://localhost:8880"),
		PrivateKeyPath: getenv("OIDC_PRIVATE_KEY_PATH", "./keys/private.pem"),

		DynamoDBRegion:            getenv("DYNAMODB_REGION", "us-east-1"),
		DynamoDBAuthCodeTable:     getenv("DYNAMODB_AUTHCODE_TABLE", "asteroid-authcodes"),
		DynamoDBAccessTokenTable:  getenv("DYNAMODB_ACCESSTOKEN_TABLE", "asteroid-accesstokens"),
		DynamoDBRefreshTokenTable: getenv("DYNAMODB_REFRESHTOKEN_TABLE", "asteroid-refreshtokens"),
		DynamoDBNonceTable:        getenv("DYNAMODB_NONCE_TABLE", "asteroid-nonces"),
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
