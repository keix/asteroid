package userinfo

import (
	"context"
	"errors"
)

// Provider abstracts user information retrieval
// Unifies both token validation (user existence) and userinfo endpoint
type Provider interface {
	// Fetch retrieves user information by subject identifier
	// Returns arbitrary userinfo claims or error if user not found
	Fetch(ctx context.Context, sub string) (map[string]any, error)
}

// Common errors
var (
	ErrUserNotFound = errors.New("user not found")
	ErrInvalidSub   = errors.New("invalid subject identifier")
)
