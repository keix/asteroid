package token

// ErrorType represents token endpoint domain errors
type ErrorType int

const (
	ErrorNone ErrorType = iota
	ErrorInvalidRequest
	ErrorInvalidClient
	ErrorInvalidGrant
	ErrorUnauthorizedClient
	ErrorUnsupportedGrantType
	ErrorInvalidScope
	ErrorInvalidTarget // RFC 8707 — requested audience not in client's allowlist
	ErrorServerError
)
