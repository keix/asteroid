package crypto

import "time"

// KeyPair represents a cryptographic key pair with metadata
type KeyPair struct {
	PrivateKey any        // Algorithm-specific private key (*rsa.PrivateKey, *ecdsa.PrivateKey)
	PublicKey  any        // Algorithm-specific public key (*rsa.PublicKey, *ecdsa.PublicKey)
	Algorithm  string     // "RS256", "ES256", "PS256"
	KeyID      string     // Unique identifier for JWKS and JWT headers
	CreatedAt  time.Time  // Key creation timestamp
	ExpiresAt  *time.Time // When key should be removed from JWKS
}

// Generator creates cryptographic key pairs for specific algorithms
type Generator interface {
	Generate() (*KeyPair, error)
	GenerateAndPersist(persister KeyPersister) (*KeyPair, error)
	Alg() string
}

// Signer signs payloads using key pairs
type Signer interface {
	Sign(payload []byte, kp *KeyPair) ([]byte, error)
}

// KeyPersister handles key storage - extensible for development/production
type KeyPersister interface {
	SaveKey(kp *KeyPair) error
	LoadKeys() ([]*KeyPair, error)
}
