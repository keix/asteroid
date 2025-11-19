package jwks

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Alg string `json:"alg"` // Algorithm
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus (for RSA)
	E   string `json:"e"`   // Exponent (for RSA)
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}
