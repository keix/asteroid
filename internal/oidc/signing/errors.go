package signing

import "errors"

// Error definitions for signing key operations
var (
	ErrKeyNotFound          = errors.New("signing key not found")
	ErrUnsupportedAlgorithm = errors.New("unsupported signing algorithm")
	ErrNoActiveKey          = errors.New("no active key for algorithm")
)
