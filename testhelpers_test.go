package asap

import (
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
)

// withClock pins the package clock for the duration of the test. Calls are
// atomic, so this is safe alongside the package's parallel tests.
func withClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := nowFn.Load().(func() time.Time)
	nowFn.Store(func() time.Time { return at })
	t.Cleanup(func() { nowFn.Store(prev) })
}

// newJWT builds an unsigned token, mirroring the constructor the tests used
// before the migration. It exists so tests can assert against token behaviour
// without holding signing keys.
func newJWT(claims Claims, method SigningMethod) Token {
	parsed := golangjwt.NewWithClaims(method.m, claims)
	return &token{parsed, claims}
}
