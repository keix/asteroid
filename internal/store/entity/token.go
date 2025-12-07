package entity

import "time"

// AccessToken represents an OAuth 2.0 access token
type AccessToken struct {
	Token     string    `json:"token" yaml:"token" dynamodbav:"token"`
	ClientID  string    `json:"client_id" yaml:"client_id" dynamodbav:"client_id"`
	UserID    string    `json:"user_id" yaml:"user_id" dynamodbav:"user_id"`
	Scope     string    `json:"scope" yaml:"scope" dynamodbav:"scope"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at" dynamodbav:"expires_at"`
}

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	Token     string    `json:"token" yaml:"token" dynamodbav:"token"`
	ClientID  string    `json:"client_id" yaml:"client_id" dynamodbav:"client_id"`
	UserID    string    `json:"user_id" yaml:"user_id" dynamodbav:"user_id"`
	Scope     string    `json:"scope" yaml:"scope" dynamodbav:"scope"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at" dynamodbav:"expires_at"`
}
