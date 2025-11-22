package entity

import "time"

// AuthCode represents an OAuth 2.0 authorization code entity
type AuthCode struct {
	Code                string    `json:"code" dynamodbav:"code"`
	ClientID            string    `json:"client_id" dynamodbav:"client_id"`
	UserID              string    `json:"user_id" dynamodbav:"user_id"`
	RedirectURI         string    `json:"redirect_uri" dynamodbav:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge" dynamodbav:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method" dynamodbav:"code_challenge_method"`
	Scope               string    `json:"scope" dynamodbav:"scope"`
	State               string    `json:"state" dynamodbav:"state"`
	Nonce               string    `json:"nonce" dynamodbav:"nonce"`
	ExpiresAt           time.Time `json:"expires_at" dynamodbav:"expires_at"`
}
