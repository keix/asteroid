package key

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// FileLoader loads RSA private keys from PEM files
type FileLoader struct {
	filepath string
}

// KeyData represents loaded key information
type KeyData struct {
	PrivateKey *rsa.PrivateKey
	KID        string
}

// NewFileLoader creates a new file-based key loader
func NewFileLoader(filepath string) *FileLoader {
	return &FileLoader{
		filepath: filepath,
	}
}

// Load reads RSA private key from PEM file and generates KID
func (l *FileLoader) Load() (*KeyData, error) {
	data, err := os.ReadFile(l.filepath)
	if err != nil {
		return nil, err
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, err
	}

	kid := generateKID(privateKey.PublicKey)

	return &KeyData{
		PrivateKey: privateKey,
		KID:        kid,
	}, nil
}

// generateKID creates a key ID from the public key
func generateKID(pub rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	sum := sha256.Sum256([]byte(n + e))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
