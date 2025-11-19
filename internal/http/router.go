package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/http/wellknown"
	"asteroid/internal/store"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	keyStore store.KeyStore,
	userStore store.UserStore,
	clientStore store.ClientStore,
	authCodeStore store.AuthCodeStore,
	cfg config.Config,
) {
	wellKnownHandler := wellknown.NewHandler(cfg.Issuer)
	jwksHandler := jwks.NewHandler(keyStore)
	authorizeHandler := authorize.NewHandler(clientStore, userStore, authCodeStore)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnownHandler.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
	}
}
