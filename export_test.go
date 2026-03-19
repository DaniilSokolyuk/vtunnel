package vtunnel

import "crypto/ed25519"

// GenerateAuthToken is exported for testing.
var GenerateAuthToken = generateAuthToken

// ValidateAuthToken is exported for testing.
var ValidateAuthToken = func(header string, pubKey ed25519.PublicKey) bool {
	return validateAuthToken(header, pubKey)
}
