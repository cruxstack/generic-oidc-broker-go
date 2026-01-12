package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateRandomString generates a cryptographically secure random string.
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}

// GeneratePKCECodes generates a code verifier and code challenge for PKCE.
// Uses the S256 challenge method (SHA-256 hash, base64url encoded).
func GeneratePKCECodes() (codeVerifier, codeChallenge string, err error) {
	// Generate code verifier (43-128 characters)
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	codeVerifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Generate code challenge (S256)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

// VerifyPKCE verifies that the code verifier matches the code challenge.
func VerifyPKCE(codeVerifier, codeChallenge string) bool {
	hash := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	return expected == codeChallenge
}

// Base64URLEncode encodes bytes to base64url without padding.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a base64url string without padding.
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
