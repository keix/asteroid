//go:build memory || !redis

package config

import "os"

type Config struct {
	Issuer string
}

func Load() Config {
	return Config{
		Issuer: getenv("OIDC_ISSUER", "http://localhost:8880"),
	}
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
