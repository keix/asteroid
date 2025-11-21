package token

// ErrorType represents token endpoint domain errors
type ErrorType int

const (
	ErrorInvalidRequest ErrorType = iota + 1
	ErrorInvalidClient
	ErrorInvalidGrant
	ErrorUnauthorizedClient
	ErrorUnsupportedGrantType
	ErrorInvalidScope
	ErrorServerError
)
