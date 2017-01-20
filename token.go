package asap

import (
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

// Token is an interface that abstracts an underlying JWT implementation.
// It can be decomposed to a byte slice for transmission and provides
// access to the JWT claims.
type Token interface {
	jwt.JWT
}

// ParseToken converts a string header value, minus the "Bearer " bit, into
// a Token.
func ParseToken(raw string) (Token, error) {
	return jws.ParseJWT([]byte(raw))
}
