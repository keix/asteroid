package http

import (
	"github.com/gin-gonic/gin"
	"asteroid/internal/config"
	"asteroid/internal/key"
	"asteroid/internal/oidc"
)

func RegisterRoutes(r *gin.Engine, kp key.KeyProvider, cfg config.Config) {
	r.GET("/.well-known/openid-configuration",
		oidc.WellKnownHandler(cfg.Issuer))

	r.GET("/jwks.json",
		oidc.JWKSHandler(kp))
}