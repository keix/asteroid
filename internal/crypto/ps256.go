package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"
)

// PS256Generator generates RSA key pairs for PS256 algorithm
type PS256Generator struct{}

// Generate creates a new RSA key pair for PS256 signing
func (g PS256Generator) Generate() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "PS256",
		KeyID:      uuid.NewString(),
		CreatedAt:  time.Now(),
	}, nil
}

// GenerateAndPersist creates a new key pair and saves it using the persister
func (g PS256Generator) GenerateAndPersist(persister KeyPersister) (*KeyPair, error) {
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
func (g PS256Generator) Alg() string {
	return "PS256"
}

// PS256Signer signs payloads using RSA-PSS with SHA-256
type PS256Signer struct{}

// Sign creates a signature using RSA PSS with SHA-256
func (s PS256Signer) Sign(payload []byte, kp *KeyPair) ([]byte, error) {
	privateKey, ok := kp.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	hash := sha256.Sum256(payload)
	return rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
}
