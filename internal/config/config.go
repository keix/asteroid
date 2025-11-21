package config

import (
	"os"
	"strconv"
)

type Config struct {
	Issuer         string
	PrivateKeyPath string

	// Store type configuration
	StoreType string // "memory", "dynamodb", "redis"

	// DynamoDB configuration
	DynamoDBRegion        string
	DynamoDBKeysTable     string
	DynamoDBUsersTable    string
	DynamoDBClientsTable  string
	DynamoDBAuthCodeTable string
	DynamoDBKeyID         string

	// Redis configuration
	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

func Load() Config {
	redisDB, _ := strconv.Atoi(getenv("REDIS_DB", "0"))

	return Config{
		Issuer:         getenv("OIDC_ISSUER", "http://localhost:8880"),
		PrivateKeyPath: getenv("OIDC_PRIVATE_KEY_PATH", "./keys/private.pem"),

		StoreType: getenv("STORE_TYPE", "memory"),

		DynamoDBRegion:        getenv("DYNAMODB_REGION", "us-east-1"),
		DynamoDBKeysTable:     getenv("DYNAMODB_KEYS_TABLE", "asteroid-keys"),
		DynamoDBUsersTable:    getenv("DYNAMODB_USERS_TABLE", "asteroid-users"),
		DynamoDBClientsTable:  getenv("DYNAMODB_CLIENTS_TABLE", "asteroid-clients"),
		DynamoDBAuthCodeTable: getenv("DYNAMODB_AUTHCODE_TABLE", "asteroid-authcodes"),
		DynamoDBKeyID:         getenv("DYNAMODB_KEY_ID", "primary-key"),

		RedisAddr:     getenv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getenv("REDIS_PASSWORD", ""),
		RedisDB:       redisDB,
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
