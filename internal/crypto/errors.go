package crypto

import "errors"

// Error definitions for crypto operations
var (
	ErrInvalidKeyType = errors.New("invalid key type for algorithm")
)
