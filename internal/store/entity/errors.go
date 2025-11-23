package entity

import "errors"

// Store layer errors
var (
	ErrUserNotFound         = errors.New("user not found")
	ErrClientNotFound       = errors.New("client not found")
	ErrAuthCodeNotFound     = errors.New("auth code not found")
	ErrAccessTokenNotFound  = errors.New("access token not found")
	ErrAccessTokenExpired   = errors.New("access token expired")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrNonceAlreadySeen     = errors.New("nonce already seen")
)
