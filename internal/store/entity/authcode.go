package entity

import "time"

// AuthCode represents an OAuth 2.0 authorization code entity
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Scope               string    `json:"scope"`
	State               string    `json:"state"`
	Nonce               string    `json:"nonce"`
	AuthTime            time.Time `json:"auth_time"`
	ExpiresAt           time.Time `json:"expires_at"`
}
