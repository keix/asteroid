//go:build redis

package config

import (
	"os"
	"strconv"
)

type Config struct {
	Issuer         string
	PrivateKeyPath string

	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

func Load() Config {
	redisDB, _ := strconv.Atoi(getenv("REDIS_DB", "0"))

	return Config{
		Issuer:         getenv("OIDC_ISSUER", "http://localhost:8880"),
		PrivateKeyPath: getenv("OIDC_PRIVATE_KEY_PATH", "./keys/private.pem"),

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
