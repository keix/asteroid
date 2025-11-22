package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/http/token"
	"asteroid/internal/http/wellknown"
	"asteroid/internal/store"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	stores *store.Stores,
	cfg config.Config,
) {
	wellKnownHandler := wellknown.NewHandler(cfg.Issuer)
	jwksHandler := jwks.NewHandler(stores.Key)
	authorizeHandler := authorize.NewHandler(stores.Client, stores.User, stores.AuthCode)
	tokenHandler := token.NewHandler(stores.AuthCode, stores.Token, stores.Client, stores.JWT)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnownHandler.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
		oidcGroup.POST("token", tokenHandler.Handle)
	}
}
