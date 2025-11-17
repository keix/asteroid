package oidc

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"asteroid/internal/key"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func JWKSHandler(kp key.KeyProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		pub := kp.PublicKey()

		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		e := base64.RawURLEncoding.EncodeToString(eBytes)

		jwk := JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kp.Kid(),
			N:   n,
			E:   e,
		}

		c.JSON(http.StatusOK, gin.H{"keys": []JWK{jwk}})
	}
}