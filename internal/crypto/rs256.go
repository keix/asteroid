package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"time"
)

// RS256Generator generates RSA key pairs for RS256 algorithm
type RS256Generator struct{}

// Generate creates a new RSA key pair for RS256 signing
func (g RS256Generator) Generate() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyID, err := GenerateKIDFromRSAPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "RS256",
		KeyID:      keyID,
		CreatedAt:  time.Now(),
	}, nil
}

// GenerateAndPersist creates a new key pair and saves it using the persister
func (g RS256Generator) GenerateAndPersist(persister KeyPersister) (*KeyPair, error) {
	kp, err := g.Generate()
	if err != nil {
		return nil, err
	}

	if err := persister.SaveKey(kp); err != nil {
		return nil, err
	}

	return kp, nil
}

// Alg returns the algorithm identifier
func (g RS256Generator) Alg() string {
	return "RS256"
}

// RS256Signer signs payloads using RSA-SHA256
type RS256Signer struct{}

// Sign creates a signature using RSA PKCS#1 v1.5 with SHA-256
func (s RS256Signer) Sign(payload []byte, kp *KeyPair) ([]byte, error) {
	privateKey, ok := kp.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	hash := sha256.Sum256(payload)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
}
