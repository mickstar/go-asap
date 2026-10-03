package asap

import (
	"errors"

	golangjwt "github.com/golang-jwt/jwt/v5"
)

// Token is an interface that abstracts an underlying JWT implementation.
// It can be decomposed to a byte slice for transmission and provides
// access to the JWT claims and protected header.
type Token interface {
	// Claims returns the token's claim set.
	Claims() Claims
	// Protected returns the token's protected header.
	Protected() Header
	// Serialize signs the token with key and returns its compact form.
	Serialize(key any) ([]byte, error)
	// Validate verifies the token's signature with key and applies the given
	// claim lifetime rules.
	Validate(key any, method SigningMethod, v ...*ValidationOptions) error
}

// CacheableKeyer is a trait for cacheable entities
type CacheableKeyer interface {
	CacheKey() string
}

// cacheableToken implements Token over a golang-jwt token.
type cacheableToken struct {
	parsed   *golangjwt.Token
	claims   Claims
	cacheKey string
}

func (t *cacheableToken) CacheKey() string {
	return t.cacheKey
}

func (t *cacheableToken) Claims() Claims {
	return t.claims
}

func (t *cacheableToken) Protected() Header {
	if t.parsed == nil {
		return nil
	}
	return Header(t.parsed.Header)
}

func (t *cacheableToken) Serialize(key any) ([]byte, error) {
	signed, err := t.parsed.SignedString(key)
	if err != nil {
		return nil, err
	}
	return []byte(signed), nil
}

// Validate verifies the signature with key and then applies the lifetime rules
// of the first validator, if any. Signature verification is restricted to the
// algorithm the caller passed in, so a token cannot talk the verifier into a
// weaker algorithm than the one selected for it.
func (t *cacheableToken) Validate(key any, method SigningMethod, v ...*ValidationOptions) error {
	parser := golangjwt.NewParser(
		golangjwt.WithValidMethods([]string{method.Alg()}),
		golangjwt.WithoutClaimsValidation(),
	)
	parsed, err := parser.Parse(t.parsed.Raw, func(*golangjwt.Token) (any, error) { return key, nil })
	if err != nil {
		return err
	}

	claims, ok := parsed.Claims.(golangjwt.MapClaims)
	if !ok {
		return errors.New("token claims are not a map")
	}

	var opts ValidationOptions
	if len(v) > 0 && v[0] != nil {
		opts = *v[0]
	}
	return Claims(claims).validateTime(nowFunc(), opts.EXP, opts.NBF)
}

// ParseToken converts a string header value, minus the "Bearer " bit, into
// a Token.
//
// Parsing does not verify the signature; the returned token has to be handed to
// a Validator. Tokens naming an algorithm the JWT library does not know are
// rejected here, as they were before.
func ParseToken(raw string) (Token, error) {
	claims := &Claims{}
	parsed, _, err := golangjwt.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return nil, err
	}
	return &cacheableToken{parsed, *claims, raw}, nil
}
