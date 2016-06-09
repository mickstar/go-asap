package methods

import (
	"github.com/SermoDigital/jose/crypto"
)

var signingMethodMap = map[string]crypto.SigningMethod{
	// ECDSA
	crypto.SigningMethodES256.Name: crypto.SigningMethodES256,
	crypto.SigningMethodES384.Name: crypto.SigningMethodES384,
	crypto.SigningMethodES512.Name: crypto.SigningMethodES512,

	// HMAC
	crypto.SigningMethodHS256.Name: crypto.SigningMethodHS256,
	crypto.SigningMethodHS384.Name: crypto.SigningMethodHS384,
	crypto.SigningMethodHS512.Name: crypto.SigningMethodHS512,

	// RSA
	crypto.SigningMethodRS256.Name: crypto.SigningMethodRS256,
	crypto.SigningMethodRS384.Name: crypto.SigningMethodRS384,
	crypto.SigningMethodRS512.Name: crypto.SigningMethodRS512,
}

func MapSigningMethod(signingMethodName string) crypto.SigningMethod {
	return signingMethodMap[signingMethodName]
}
