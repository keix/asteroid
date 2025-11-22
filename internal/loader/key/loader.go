package key

import "crypto/rsa"

// Loader interface for different key loading strategies
type Loader interface {
	Load() (*KeyData, error)
}

// LoaderType represents different key loading strategies
type LoaderType string

const (
	LoaderTypeFile LoaderType = "file"
	// Future: LoaderTypeAWSKMS, LoaderTypeVault, etc.
)

// NewLoader creates a key loader based on the specified type and configuration
func NewLoader(loaderType LoaderType, config string) Loader {
	switch loaderType {
	case LoaderTypeFile:
		return NewFileLoader(config) // config is filepath
	default:
		return NewFileLoader(config) // fallback to file
	}
}

// LoadRSAKey is a convenience function to load an RSA private key
func LoadRSAKey(loaderType LoaderType, config string) (*rsa.PrivateKey, string, error) {
	loader := NewLoader(loaderType, config)
	keyData, err := loader.Load()
	if err != nil {
		return nil, "", err
	}
	return keyData.PrivateKey, keyData.KID, nil
}
