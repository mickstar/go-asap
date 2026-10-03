package asap

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
)

// Errors reported while validating token claims. They keep the text the
// previous underlying JWT implementation used so callers matching on them (or
// on the message) keep working.
var (
	// ErrTokenIsExpired is returned when the "exp" claim is beyond its leeway.
	ErrTokenIsExpired = errors.New("token is expired")
	// ErrTokenNotYetValid is returned when the "nbf" claim is beyond its leeway.
	ErrTokenNotYetValid = errors.New("token is not yet valid")
)

// nowFn holds the package clock. It is an atomic value so tests can swap it
// without racing against the parallel tests in this package.
var nowFn atomic.Value

// nowFunc returns the current time according to the package clock.
func nowFunc() time.Time { return nowFn.Load().(func() time.Time)() }

func init() {
	nowFn.Store(func() time.Time { return time.Now().UTC() })
}

// SigningMethod identifies a JWS signing algorithm.
//
// It replaces the signing method type of the JWT library this package used to
// depend on. Only the algorithms ASAP defines can be represented; construct one
// from the exported values below rather than from a struct literal.
type SigningMethod struct {
	alg string
	m   golangjwt.SigningMethod
}

// Alg returns the "alg" header value of the signing method.
func (s SigningMethod) Alg() string { return s.alg }

// The signing methods ASAP accepts, mirroring the previous library's names.
var (
	SigningMethodES256 = SigningMethod{methodES256, golangjwt.SigningMethodES256}
	SigningMethodES384 = SigningMethod{methodES384, golangjwt.SigningMethodES384}
	SigningMethodES512 = SigningMethod{methodES512, golangjwt.SigningMethodES512}

	SigningMethodRS256 = SigningMethod{methodRS256, golangjwt.SigningMethodRS256}
	SigningMethodRS384 = SigningMethod{methodRS384, golangjwt.SigningMethodRS384}
	SigningMethodRS512 = SigningMethod{methodRS512, golangjwt.SigningMethodRS512}

	SigningMethodPS256 = SigningMethod{methodPS256, golangjwt.SigningMethodPS256}
	SigningMethodPS384 = SigningMethod{methodPS384, golangjwt.SigningMethodPS384}
	SigningMethodPS512 = SigningMethod{methodPS512, golangjwt.SigningMethodPS512}
)

// ValidationOptions holds the options that apply when a token's registered
// claims are validated. Only the leeway fields are used by ASAP; they mirror
// the option struct of the JWT library this package used to depend on.
//
// It is not named Validator because this package already exports a Validator
// interface for validating tokens.
type ValidationOptions struct {
	// EXP is the leeway applied to the "exp" claim.
	EXP time.Duration
	// NBF is the leeway applied to the "nbf" claim.
	NBF time.Duration

	_ struct{} // require explicitly named fields, as before
}

// Header is a JWT protected header.
type Header map[string]any

// Get returns the value of the given header parameter, or nil.
func (h Header) Get(key string) any {
	if h == nil {
		return nil
	}
	return h[key]
}

// Set sets the given header parameter.
func (h Header) Set(key string, val any) { h[key] = val }

// Del removes the given header parameter.
func (h Header) Del(key string) { delete(h, key) }

// Claims is a set of JWT claims. It is a plain map whose helper accessors match
// the ones the previous implementation exposed.
type Claims map[string]any

// Get returns the value for key, or nil.
func (c Claims) Get(key string) any {
	if c == nil {
		return nil
	}
	return c[key]
}

// Set sets Claims[key] = val, overwriting without warning.
func (c Claims) Set(key string, val any) { c[key] = val }

// Del removes key from the claims.
func (c Claims) Del(key string) { delete(c, key) }

// Has reports whether a value exists for key.
func (c Claims) Has(key string) bool {
	_, ok := c[key]
	return ok
}

// Issuer retrieves claim "iss".
func (c Claims) Issuer() (string, bool) {
	v, ok := c.Get("iss").(string)
	return v, ok
}

// Subject retrieves claim "sub".
func (c Claims) Subject() (string, bool) {
	v, ok := c.Get("sub").(string)
	return v, ok
}

// JWTID retrieves claim "jti".
func (c Claims) JWTID() (string, bool) {
	v, ok := c.Get("jti").(string)
	return v, ok
}

// Audience retrieves claim "aud" as a list. A single string is normalised to a
// one element list, and a list whose elements are not all strings is rejected,
// matching the previous implementation.
func (c Claims) Audience() ([]string, bool) {
	switch t := c.Get("aud").(type) {
	case string:
		return []string{t}, true
	case []string:
		return t, true
	case []any:
		return stringify(t)
	case any:
		return stringify(t)
	}
	return nil, false
}

func stringify(a ...any) ([]string, bool) {
	if len(a) == 0 {
		return nil, false
	}
	s := make([]string, len(a))
	for i := range a {
		str, ok := a[i].(string)
		if !ok {
			return nil, false
		}
		s[i] = str
	}
	return s, true
}

// Expiration retrieves claim "exp".
func (c Claims) Expiration() (time.Time, bool) { return c.GetTime("exp") }

// NotBefore retrieves claim "nbf".
func (c Claims) NotBefore() (time.Time, bool) { return c.GetTime("nbf") }

// IssuedAt retrieves claim "iat".
func (c Claims) IssuedAt() (time.Time, bool) { return c.GetTime("iat") }

// GetTime returns the numeric claim key as a time, in seconds since the epoch.
// Numeric values parsed from JSON are always float64; other numeric types are
// accepted for claims that were set in memory.
func (c Claims) GetTime(key string) (time.Time, bool) {
	switch t := c.Get(key).(type) {
	case int:
		return time.Unix(int64(t), 0), true
	case int32:
		return time.Unix(int64(t), 0), true
	case int64:
		return time.Unix(int64(t), 0), true
	case uint:
		return time.Unix(int64(t), 0), true
	case uint32:
		return time.Unix(int64(t), 0), true
	case uint64:
		return time.Unix(int64(t), 0), true
	case float64:
		return time.Unix(int64(t), 0), true
	default:
		return time.Time{}, false
	}
}

// SetTime stores t as the number of seconds since the epoch for key.
func (c Claims) SetTime(key string, t time.Time) { c.Set(key, t.Unix()) }

// SetIssuer sets claim "iss".
func (c Claims) SetIssuer(issuer string) { c.Set("iss", issuer) }

// SetSubject sets claim "sub".
func (c Claims) SetSubject(subject string) { c.Set("sub", subject) }

// SetJWTID sets claim "jti".
func (c Claims) SetJWTID(uniqueID string) { c.Set("jti", uniqueID) }

// SetIssuedAt sets claim "iat".
func (c Claims) SetIssuedAt(issuedAt time.Time) { c.SetTime("iat", issuedAt) }

// SetExpiration sets claim "exp".
func (c Claims) SetExpiration(expiration time.Time) { c.SetTime("exp", expiration) }

// SetNotBefore sets claim "nbf".
func (c Claims) SetNotBefore(notBefore time.Time) { c.SetTime("nbf", notBefore) }

// SetAudience sets claim "aud". A single audience is stored as a bare string
// and anything else as a list, matching the previous implementation's wire
// format.
func (c Claims) SetAudience(audience ...string) {
	if len(audience) == 1 {
		c.Set("aud", audience[0])
	} else {
		c.Set("aud", audience)
	}
}

// RemoveIssuer deletes claim "iss".
func (c Claims) RemoveIssuer() { c.Del("iss") }

// RemoveSubject deletes claim "sub".
func (c Claims) RemoveSubject() { c.Del("sub") }

// RemoveAudience deletes claim "aud".
func (c Claims) RemoveAudience() { c.Del("aud") }

// RemoveExpiration deletes claim "exp".
func (c Claims) RemoveExpiration() { c.Del("exp") }

// RemoveNotBefore deletes claim "nbf".
func (c Claims) RemoveNotBefore() { c.Del("nbf") }

// RemoveIssuedAt deletes claim "iat".
func (c Claims) RemoveIssuedAt() { c.Del("iat") }

// RemoveJWTID deletes claim "jti".
func (c Claims) RemoveJWTID() { c.Del("jti") }

// validateTime enforces the claim lifetime rules the previous implementation
// applied: "exp" is optional, and "nbf" is optional. The comparisons are
// deliberately inclusive at the leeway boundary, as before.
func (c Claims) validateTime(now time.Time, expLeeway, nbfLeeway time.Duration) error {
	if exp, ok := c.Expiration(); ok {
		if now.After(exp.Add(expLeeway)) {
			return ErrTokenIsExpired
		}
	}
	if nbf, ok := c.NotBefore(); ok {
		if !now.After(nbf.Add(-nbfLeeway)) {
			return ErrTokenNotYetValid
		}
	}
	return nil
}

// MarshalJSON implements json.Marshaler. Empty claims serialise to nothing, as
// they did before.
func (c Claims) MarshalJSON() ([]byte, error) {
	if len(c) == 0 {
		return nil, nil
	}
	return json.Marshal(map[string]any(c))
}

// UnmarshalJSON implements json.Unmarshaler, with the same numeric handling as
// the previous implementation (every JSON number becomes a float64).
func (c *Claims) UnmarshalJSON(b []byte) error {
	if b == nil {
		return nil
	}
	var tmp map[string]any
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*c = tmp
	return nil
}

// The methods below satisfy the golang-jwt claims interface so that a Claims
// value can be handed to the parser directly.

func (c Claims) GetExpirationTime() (*golangjwt.NumericDate, error) {
	return golangjwt.MapClaims(c).GetExpirationTime()
}

func (c Claims) GetIssuedAt() (*golangjwt.NumericDate, error) {
	return golangjwt.MapClaims(c).GetIssuedAt()
}

func (c Claims) GetNotBefore() (*golangjwt.NumericDate, error) {
	return golangjwt.MapClaims(c).GetNotBefore()
}

func (c Claims) GetIssuer() (string, error) { return golangjwt.MapClaims(c).GetIssuer() }

func (c Claims) GetSubject() (string, error) { return golangjwt.MapClaims(c).GetSubject() }

func (c Claims) GetAudience() (golangjwt.ClaimStrings, error) {
	return golangjwt.MapClaims(c).GetAudience()
}
