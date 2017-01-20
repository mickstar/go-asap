package asap

import "github.com/SermoDigital/jose/crypto"

const (
	ClaimAlgorithm  = "alg"
	ClaimKeyID      = "kid"
	ClaimIssuer     = "iss"
	ClaimExpiration = "exp"
	ClaimIssuedAt   = "iat"
	ClaimAudience   = "aud"
	ClaimTokenID    = "jti"
	ClaimSubject    = "sub"
	ClaimNotBefore  = "nbf"
)

const (
	methodES256 = "ES256"
	methodES384 = "ES384"
	methodES512 = "ES512"

	methodRS256 = "RS256"
	methodRS384 = "RS384"
	methodRS512 = "RS512"
)

var signingMethodMap = map[string]crypto.SigningMethod{
	// ECDSA
	methodES256: crypto.SigningMethodES256,
	methodES384: crypto.SigningMethodES384,
	methodES512: crypto.SigningMethodES512,

	// RSA
	methodRS256: crypto.SigningMethodRS256,
	methodRS384: crypto.SigningMethodRS384,
	methodRS512: crypto.SigningMethodRS512,
}
