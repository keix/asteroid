package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/http/token"
	"asteroid/internal/http/wellknown"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	stores *store.Stores,
	signingService *signing.Service,
	cfg config.Config,
) {
	wellKnownHandler := wellknown.NewHandler(cfg.Issuer)
	jwksHandler := jwks.NewHandler(signingService)
	authorizeHandler := authorize.NewHandler(stores.Client, stores.User, stores.AuthCode, stores.Nonce)
	tokenHandler := token.NewHandler(stores.AuthCode, stores.Token, stores.Client, signingService, cfg.Issuer)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnownHandler.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
		oidcGroup.POST("token", tokenHandler.Handle)
	}
}
