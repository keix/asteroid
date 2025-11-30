package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"time"
)

// ES256Generator generates ECDSA key pairs for ES256 algorithm
type ES256Generator struct{}

// Generate creates a new ECDSA key pair using P-256 curve
func (g ES256Generator) Generate() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyID, err := GenerateKIDFromECDSAPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "ES256",
		KeyID:      keyID,
		CreatedAt:  time.Now(),
	}, nil
}

// GenerateAndPersist creates a new key pair and saves it using the persister
func (g ES256Generator) GenerateAndPersist(persister KeyPersister) (*KeyPair, error) {
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
func (g ES256Generator) Alg() string {
	return "ES256"
}

// ES256Signer signs payloads using ECDSA-SHA256
type ES256Signer struct{}

// Sign creates a signature using ECDSA with P-256 curve and SHA-256
func (s ES256Signer) Sign(payload []byte, kp *KeyPair) ([]byte, error) {
	privateKey, ok := kp.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	hash := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}
