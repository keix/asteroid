package persister

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asteroid/internal/crypto"
)

// File implements crypto.KeyPersister for development environments
// Stores keys as PEM files in a directory structure
type File struct {
	KeyDir string
}

// New creates a new file-based key persister
func New(keyDir string) *File {
	return &File{
		KeyDir: keyDir,
	}
}

// SaveKey saves a key pair to the filesystem
func (f *File) SaveKey(kp *crypto.KeyPair) error {
	// Ensure key directory exists
	if err := os.MkdirAll(f.KeyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save private key as PEM (kid-based filename)
	privateKeyPath := filepath.Join(f.KeyDir, fmt.Sprintf("%s.pem", kp.KeyID))
	if err := f.savePrivateKeyPEM(kp, privateKeyPath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	return nil
}

// LoadKeys loads all valid key pairs from the filesystem
func (f *File) LoadKeys() ([]*crypto.KeyPair, error) {
	// Check if key directory exists
	if _, err := os.Stat(f.KeyDir); os.IsNotExist(err) {
		return []*crypto.KeyPair{}, nil // No keys directory, return empty
	}

	entries, err := os.ReadDir(f.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read key directory: %w", err)
	}

	var keyPairs []*crypto.KeyPair

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pem") {
			continue // Only process PEM files
		}

		keyPair, err := f.loadKeyPairFromPEM(entry.Name())
		if err != nil {
			// Log error but continue with other keys
			fmt.Printf("Warning: failed to load key %s: %v\n", entry.Name(), err)
			continue
		}

		keyPairs = append(keyPairs, keyPair)
	}

	return keyPairs, nil
}

// savePrivateKeyPEM saves the private key in PEM format
func (f *File) savePrivateKeyPEM(kp *crypto.KeyPair, path string) error {
	var derBytes []byte
	var pemType string
	var err error

	switch privateKey := kp.PrivateKey.(type) {
	case *rsa.PrivateKey:
		derBytes = x509.MarshalPKCS1PrivateKey(privateKey)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		derBytes, err = x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return err
		}
		pemType = "EC PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  pemType,
		Bytes: derBytes,
	})
}

// loadKeyPairFromPEM loads a key pair from PEM file and generates kid
func (f *File) loadKeyPairFromPEM(filename string) (*crypto.KeyPair, error) {
	path := filepath.Join(f.KeyDir, filename)

	privateKey, publicKey, err := f.loadPrivateKeyPEM(path)
	if err != nil {
		return nil, err
	}

	// Generate kid from public key
	var keyID string
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		keyID, err = crypto.GenerateKIDFromRSAPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("failed to generate kid for RSA key: %w", err)
		}
	case *ecdsa.PublicKey:
		keyID, err = crypto.GenerateKIDFromECDSAPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("failed to generate kid for ECDSA key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}

	return &crypto.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  "ES256", // Fixed algorithm
		KeyID:      keyID,
		CreatedAt:  time.Now(), // Current time as we don't have metadata
	}, nil
}

// loadPrivateKeyPEM loads a private key from PEM file
func (f *File) loadPrivateKeyPEM(path string) (any, any, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, &privateKey.PublicKey, nil

	case "EC PRIVATE KEY":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		return privateKey, &privateKey.PublicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}
