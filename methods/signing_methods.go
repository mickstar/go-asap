package methods

import (
	"github.com/SermoDigital/jose/crypto"
)

const (
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"

	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
)

var SigningMethodMap = map[string]crypto.SigningMethod{
	// ECDSA
	ES256: crypto.SigningMethodES256,
	ES384: crypto.SigningMethodES384,
	ES512: crypto.SigningMethodES512,

	// RSA
	RS256: crypto.SigningMethodRS256,
	RS384: crypto.SigningMethodRS384,
	RS512: crypto.SigningMethodRS512,
}
