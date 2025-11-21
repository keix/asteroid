//go:build memory || (!dynamodb && !redis)

package config

import "os"

type Config struct {
	Issuer         string
	PrivateKeyPath string
}

func Load() Config {
	return Config{
		Issuer:         getenv("OIDC_ISSUER", "http://localhost:8880"),
		PrivateKeyPath: getenv("OIDC_PRIVATE_KEY_PATH", "./keys/private.pem"),
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}