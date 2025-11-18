package oidc

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"asteroid/internal/store"

	"github.com/gin-gonic/gin"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func JWKSHandler(keyStore store.KeyStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		privateKey, err := keyStore.GetSigningKey(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get signing key"})
			return
		}

		kid, err := keyStore.GetKid(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get key id"})
			return
		}

		pub := &privateKey.PublicKey
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		e := base64.RawURLEncoding.EncodeToString(eBytes)

		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   n,
			E:   e,
		}

		c.JSON(http.StatusOK, gin.H{"keys": []JWK{jwk}})
	}
}
