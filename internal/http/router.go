package http

import (
	"asteroid/internal/config"
	"asteroid/internal/oidc"
	"asteroid/internal/store"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine, keyStore store.KeyStore, cfg config.Config) {
	r.GET("/.well-known/openid-configuration",
		oidc.WellKnownHandler(cfg.Issuer))

	r.GET("/jwks.json",
		oidc.JWKSHandler(keyStore))
}
