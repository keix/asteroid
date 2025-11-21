package jwt

// IDTokenClaims represents the claims in an ID Token (JWT)
type IDTokenClaims struct {
	// Standard JWT claims
	Issuer    string `json:"iss"`             // Issuer
	Subject   string `json:"sub"`             // Subject (user ID)
	Audience  string `json:"aud"`             // Audience (client ID)
	ExpiresAt int64  `json:"exp"`             // Expiration time
	IssuedAt  int64  `json:"iat"`             // Issued at
	AuthTime  int64  `json:"auth_time"`       // Authentication time
	Nonce     string `json:"nonce,omitempty"` // Optional nonce
}
