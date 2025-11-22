package token

import (
	"crypto/sha256"
	"encoding/base64"
)

// validatePKCE verifies code_verifier against code_challenge per RFC 7636
func validatePKCE(codeChallenge, codeVerifier, codeChallengeMethod string) bool {
	if codeChallenge == "" || codeVerifier == "" {
		return false
	}

	switch codeChallengeMethod {
	case "S256":
		// Base64URL(SHA256(code_verifier)) == code_challenge
		hash := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return codeChallenge == expectedChallenge
	case "plain":
		// code_verifier == code_challenge (not recommended, rejected in authorization)
		return codeChallenge == codeVerifier
	default:
		return false
	}
}
