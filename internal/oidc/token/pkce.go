package token

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

// validatePKCE verifies code_verifier against code_challenge per RFC 7636
// Only supports S256 method for security reasons
func validatePKCE(codeChallenge, codeVerifier, codeChallengeMethod string) bool {
	if codeChallenge == "" || codeVerifier == "" {
		return false
	}

	// Only S256 method is supported for security
	if codeChallengeMethod != "S256" {
		return false
	}

	// Validate code_verifier per RFC 7636 Section 4.1
	if !isValidCodeVerifier(codeVerifier) {
		return false
	}

	// Validate code_challenge format (base64url)
	if !isValidBase64URL(codeChallenge) {
		return false
	}

	// Base64URL(SHA256(code_verifier)) == code_challenge
	hash := sha256.Sum256([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return codeChallenge == expectedChallenge
}

// isValidCodeVerifier validates code_verifier per RFC 7636 Section 4.1
// Length: 43-128 characters, unreserved characters only [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
func isValidCodeVerifier(codeVerifier string) bool {
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return false
	}

	// RFC 7636: unreserved characters only
	matched, _ := regexp.MatchString(`^[A-Za-z0-9._~-]+$`, codeVerifier)
	return matched
}

// isValidBase64URL validates that the string is valid base64url encoding
func isValidBase64URL(s string) bool {
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}
