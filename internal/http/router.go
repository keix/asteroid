package http

import (
	"asteroid/internal/config"
	"asteroid/internal/http/authorize"
	"asteroid/internal/http/jwks"
	"asteroid/internal/http/token"
	"asteroid/internal/http/wellknown"
	"asteroid/internal/oidc/jwt"
	"asteroid/internal/store"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	r *gin.Engine,
	keyStore store.KeyStore,
	userStore store.UserStore,
	clientStore store.ClientStore,
	authCodeStore store.AuthCodeStore,
	tokenStore store.TokenStore,
	cfg config.Config,
) {
	jwtService := jwt.NewService(keyStore, cfg.Issuer)

	wellKnownHandler := wellknown.NewHandler(cfg.Issuer)
	jwksHandler := jwks.NewHandler(keyStore)
	authorizeHandler := authorize.NewHandler(clientStore, userStore, authCodeStore)
	tokenHandler := token.NewHandler(authCodeStore, tokenStore, clientStore, jwtService)

	oidcGroup := r.Group("/")
	{
		oidcGroup.GET(".well-known/openid-configuration", wellKnownHandler.Handle)
		oidcGroup.GET("jwks.json", jwksHandler.Handle)
		oidcGroup.GET("authorize", authorizeHandler.Handle)
		oidcGroup.POST("token", tokenHandler.Handle)
	}
}
