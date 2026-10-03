package asap

import (
	"encoding/json"
	"errors"
	"strings"

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

// errNotAJWT mirrors the error the previous implementation returned when a JWS
// payload was not a set of claims.
var errNotAJWT = errors.New("JWS is not a JWT")

// token implements Token over a golang-jwt token.
type token struct {
	parsed *golangjwt.Token
	claims Claims
}

func (t *token) Claims() Claims {
	return t.claims
}

func (t *token) Protected() Header {
	if t.parsed == nil {
		return nil
	}
	return Header(t.parsed.Header)
}

func (t *token) Serialize(key any) ([]byte, error) {
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
func (t *token) Validate(key any, method SigningMethod, v ...*ValidationOptions) error {
	parser := golangjwt.NewParser(
		golangjwt.WithValidMethods([]string{method.Alg()}),
		golangjwt.WithoutClaimsValidation(),
	)
	parsed, err := parser.Parse(t.parsed.Raw, func(*golangjwt.Token) (any, error) { return key, nil })
	if err != nil {
		return err
	}

	claims, ok := parsed.Claims.(golangjwt.MapClaims)
	if !ok || claims == nil {
		return errNotAJWT
	}

	var opts ValidationOptions
	if len(v) > 0 && v[0] != nil {
		opts = *v[0]
	}
	return Claims(claims).validateTime(nowFunc(), opts.EXP, opts.NBF)
}

// parsedToken is a token read off the wire. It keeps the serialized form, which
// is the cache key the caching validator indexed on before the migration.
//
// Only parsed tokens satisfy CacheableKeyer. A freshly minted token has no
// serialized form yet, so its cache key would be empty and every minted token
// would collide under it; the previous implementation did not expose the trait
// on those tokens either.
type parsedToken struct {
	token
	raw string
}

func (t *parsedToken) CacheKey() string {
	return t.raw
}

// ParseToken converts a string header value, minus the "Bearer " bit, into
// a Token.
//
// Parsing does not verify the signature; the returned token has to be handed to
// a Validator. Tokens naming an algorithm the JWT library does not know, and
// tokens whose payload is not a claims object, are rejected here as they were
// before.
func ParseToken(raw string) (Token, error) {
	parser := golangjwt.NewParser()
	claims := &Claims{}
	parsed, _, err := parser.ParseUnverified(raw, claims)
	if err != nil {
		return nil, err
	}
	// encoding/json resolves the literal null to a nil interface instead of
	// calling Claims.UnmarshalJSON, so the parser alone cannot distinguish a
	// null payload from a claims object. The previous implementation asserted
	// that the decoded payload was an object, so check it the same way.
	if !isClaimsObject(parser, raw) {
		return nil, errNotAJWT
	}
	return &parsedToken{token{parsed, *claims}, raw}, nil
}

// isClaimsObject reports whether the payload of raw decodes to a JSON object.
func isClaimsObject(parser *golangjwt.Parser, raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := parser.DecodeSegment(parts[1])
	if err != nil {
		return false
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return false
	}
	_, ok := decoded.(map[string]any)
	return ok
}
