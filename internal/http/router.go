package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/http/token"
	"asteroid/internal/http/wellknown"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store"
	"asteroid/internal/userinfo"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	cfg config.Config,
	stores *store.Stores,
	userinfoProvider userinfo.Provider,
	signingService *signing.Service,
) {
	wellKnownHandler := wellknown.NewHandler(cfg.Issuer)
	authorizeHandler := authorize.NewHandler(stores.Client, stores.AuthCode, stores.Nonce, userinfoProvider)
	tokenHandler := token.NewHandler(cfg.Issuer, stores.Client, stores.AuthCode, stores.Token, userinfoProvider, signingService)
	jwksHandler := jwks.NewHandler(signingService)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnownHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
		oidcGroup.POST("token", tokenHandler.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
	}
}
