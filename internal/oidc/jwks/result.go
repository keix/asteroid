package jwks

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Alg string `json:"alg"` // Algorithm
	Kid string `json:"kid"` // Key ID

	N string `json:"n,omitempty"` // Modulus (for RSA)
	E string `json:"e,omitempty"` // Exponent (for RSA)

	Crv string `json:"crv,omitempty"` // Curve (for ECDSA)
	X   string `json:"x,omitempty"`   // X coordinate (for ECDSA)
	Y   string `json:"y,omitempty"`   // Y coordinate (for ECDSA)
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}
