package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type LocalKeyProvider struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func NewLocalKeyProvider(path string) (KeyProvider, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	priv, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return nil, err
	}

	kid := generateKID(priv.PublicKey)

	return &LocalKeyProvider{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		kid:        kid,
	}, nil
}

func (p *LocalKeyProvider) PublicKey() *rsa.PublicKey {
	return p.publicKey
}

func (p *LocalKeyProvider) Kid() string {
	return p.kid
}

func (p *LocalKeyProvider) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, digest[:])
}

func generateKID(pub rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	sum := sha256.Sum256([]byte(n + e))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}