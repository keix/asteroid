package entity

import "errors"

// Store layer errors
var (
	ErrUserNotFound     = errors.New("user not found")
	ErrClientNotFound   = errors.New("client not found")
	ErrAuthCodeNotFound = errors.New("auth code not found")
)
