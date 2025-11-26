package persister

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

	// Save private key as PEM
	privateKeyPath := filepath.Join(f.KeyDir, fmt.Sprintf("%s-%s.pem", kp.Algorithm, kp.KeyID))
	if err := f.savePrivateKeyPEM(kp, privateKeyPath); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Save metadata as JSON
	metadataPath := filepath.Join(f.KeyDir, fmt.Sprintf("%s-%s.json", kp.Algorithm, kp.KeyID))
	if err := f.saveMetadata(kp, metadataPath); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
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
	processedKeys := make(map[string]bool)

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue // Only process metadata files
		}

		// Extract key ID from filename
		baseName := strings.TrimSuffix(entry.Name(), ".json")
		if processedKeys[baseName] {
			continue // Already processed this key
		}

		keyPair, err := f.loadKeyPair(baseName)
		if err != nil {
			// Log error but continue with other keys
			fmt.Printf("Warning: failed to load key %s: %v\n", baseName, err)
			continue
		}

		keyPairs = append(keyPairs, keyPair)
		processedKeys[baseName] = true
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

// saveMetadata saves key metadata as JSON
func (f *File) saveMetadata(kp *crypto.KeyPair, path string) error {
	metadata := map[string]interface{}{
		"algorithm":  kp.Algorithm,
		"key_id":     kp.KeyID,
		"created_at": kp.CreatedAt,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(metadata)
}

// loadKeyPair loads a key pair from PEM and JSON files
func (f *File) loadKeyPair(baseName string) (*crypto.KeyPair, error) {
	// Load metadata
	metadataPath := filepath.Join(f.KeyDir, baseName+".json")
	metadata, err := f.loadMetadata(metadataPath)
	if err != nil {
		return nil, err
	}

	// Load private key
	pemPath := filepath.Join(f.KeyDir, baseName+".pem")
	privateKey, publicKey, err := f.loadPrivateKeyPEM(pemPath)
	if err != nil {
		return nil, err
	}

	return &crypto.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  metadata["algorithm"].(string),
		KeyID:      metadata["key_id"].(string),
	}, nil
}

// loadMetadata loads metadata from JSON file
func (f *File) loadMetadata(path string) (map[string]interface{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var metadata map[string]interface{}
	if err := json.NewDecoder(file).Decode(&metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// loadPrivateKeyPEM loads a private key from PEM file
func (f *File) loadPrivateKeyPEM(path string) (interface{}, interface{}, error) {
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
