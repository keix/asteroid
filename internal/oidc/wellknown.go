package oidc

import (
	"github.com/gin-gonic/gin"
)

type WellKnownHandler struct {
	issuer string
}

func NewWellKnownHandler(issuer string) *WellKnownHandler {
	return &WellKnownHandler{
		issuer: issuer,
	}
}

func (h *WellKnownHandler) Handle(c *gin.Context) {
	c.JSON(200, gin.H{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/authorize",
		"token_endpoint":                        h.issuer + "/token",
		"userinfo_endpoint":                     h.issuer + "/userinfo",
		"jwks_uri":                              h.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}
