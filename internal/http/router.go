package http

import (
	"asteroid/internal/config"
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
	jwks := oidc.NewJWKSHandler(keyStore)
	authorize := oidc.NewAuthorizeHandler(clientStore, userStore, authCodeStore)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnown.Handle)
		oidcGroup.GET("jwks.json", jwks.Handle)
		oidcGroup.GET("authorize", authorize.Handle)
	}
}
