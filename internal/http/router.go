package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/oidc"
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
	wellKnown := oidc.NewWellKnownHandler(cfg.Issuer)
	jwksHandler := jwks.NewHandler(keyStore)
	authorizeHandler := authorize.NewHandler(clientStore, userStore, authCodeStore)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnown.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
	}
}
