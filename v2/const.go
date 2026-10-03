package asap

const (
	// ClaimAlgorithm is the JWT specific encryption algorithm claim.
	ClaimAlgorithm = "alg"
	// ClaimKeyID is the JWT specified key identifier claim.
	ClaimKeyID = "kid"
	// ClaimIssuer is the JWT specified token issuer claim.
	ClaimIssuer = "iss"
	// ClaimExpiration is the JWT specified token expiration claim.
	ClaimExpiration = "exp"
	// ClaimIssuedAt is the JWT specified issued at claim.
	ClaimIssuedAt = "iat"
	// ClaimAudience is the JWT specified audience claim.
	ClaimAudience = "aud"
	// ClaimTokenID is the JWT specified JWT ID claim.
	ClaimTokenID = "jti"
	// ClaimSubject is the JWT specified subject claim.
	ClaimSubject = "sub"
	// ClaimNotBefore is the JWT specified not before claim.
	ClaimNotBefore = "nbf"
)

const (
	methodES256 = "ES256"
	methodES384 = "ES384"
	methodES512 = "ES512"

	methodRS256 = "RS256"
	methodRS384 = "RS384"
	methodRS512 = "RS512"

	methodPS256 = "PS256"
	methodPS384 = "PS384"
	methodPS512 = "PS512"
)

// signingMethodMap is the allow list of algorithms ASAP accepts. A token naming
// anything else is rejected by AlgorithmValidator.
var signingMethodMap = map[string]SigningMethod{
	// ECDSA
	methodES256: SigningMethodES256,
	methodES384: SigningMethodES384,
	methodES512: SigningMethodES512,

	// RSA PKCS#1 v1.5
	methodRS256: SigningMethodRS256,
	methodRS384: SigningMethodRS384,
	methodRS512: SigningMethodRS512,

	// RSA-PSS
	methodPS256: SigningMethodPS256,
	methodPS384: SigningMethodPS384,
	methodPS512: SigningMethodPS512,
}
