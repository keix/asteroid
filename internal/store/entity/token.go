package entity

import "time"

// AccessToken represents an OAuth 2.0 access token
type AccessToken struct {
	Token     string    `json:"token" yaml:"token"`
	ClientID  string    `json:"client_id" yaml:"client_id"`
	UserID    string    `json:"user_id" yaml:"user_id"`
	Scope     string    `json:"scope" yaml:"scope"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	Token     string    `json:"token" yaml:"token"`
	ClientID  string    `json:"client_id" yaml:"client_id"`
	UserID    string    `json:"user_id" yaml:"user_id"`
	Scope     string    `json:"scope" yaml:"scope"`
	AuthTime  time.Time `json:"auth_time" yaml:"auth_time"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
}
