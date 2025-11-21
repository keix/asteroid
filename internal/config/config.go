package config

import "os"

type Config struct {
	Issuer         string
	PrivateKeyPath string

	// DynamoDB configuration
	DynamoDBRegion        string
	DynamoDBKeysTable     string
	DynamoDBUsersTable    string
	DynamoDBClientsTable  string
	DynamoDBAuthCodeTable string
	DynamoDBKeyID         string
}

func Load() Config {
	return Config{
		Issuer:         getenv("OIDC_ISSUER", "http://localhost:8880"),
		PrivateKeyPath: getenv("OIDC_PRIVATE_KEY_PATH", "./keys/private.pem"),

		DynamoDBRegion:        getenv("DYNAMODB_REGION", "us-east-1"),
		DynamoDBKeysTable:     getenv("DYNAMODB_KEYS_TABLE", "asteroid-keys"),
		DynamoDBUsersTable:    getenv("DYNAMODB_USERS_TABLE", "asteroid-users"),
		DynamoDBClientsTable:  getenv("DYNAMODB_CLIENTS_TABLE", "asteroid-clients"),
		DynamoDBAuthCodeTable: getenv("DYNAMODB_AUTHCODE_TABLE", "asteroid-authcodes"),
		DynamoDBKeyID:         getenv("DYNAMODB_KEY_ID", "primary-key"),
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
