package asap

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// These two tests pin the controls that an independent review found were
// carrying security weight with no coverage at all:
//
//   - token.Validate passes WithValidMethods(method.Alg()). Deleting that single
//     line left this entire suite green while turning an HS256 algorithm
//     confusion forgery into an accepted token.
//   - Claims.validateTime exists to reproduce the previous implementation's
//     inclusive exp/nbf leeway boundary. Shifting either comparison by one
//     instant also left the suite green, because the fixtures sit minutes away
//     from the boundary.
//
// Both defects were demonstrated by mutation before being pinned here.

// forgeCompact builds a compact JWS whose signature is HMAC over secret, or
// empty for alg "none". It exists so the test can produce the tokens an attacker
// would, rather than tokens this package is willing to mint.
func forgeCompact(t *testing.T, alg string, payload map[string]any, secret []byte) string {
	t.Helper()

	header, err := json.Marshal(map[string]any{"alg": alg, "kid": parityIssuer + "/key1", "typ": "JWT"})
	require.NoError(t, err)
	body, err := json.Marshal(payload)
	require.NoError(t, err)

	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)

	var mac hash.Hash
	switch alg {
	case "none":
		return signing + "."
	case "HS256":
		mac = hmac.New(sha256.New, secret)
	case "HS384":
		mac = hmac.New(sha512.New384, secret)
	case "HS512":
		mac = hmac.New(sha512.New, secret)
	default:
		t.Fatalf("forgeCompact: unsupported alg %q", alg)
	}
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestValidateRejectsAlgorithmSubstitution is the regression guard for
// WithValidMethods. A caller pins a signing method; a token naming a different
// one must not verify, even when the key material happens to be usable under
// that other algorithm — which is exactly the shape of an HMAC-with-the-public-key
// confusion attack.
func TestValidateRejectsAlgorithmSubstitution(t *testing.T) {
	priv, pub := loadParityKeys(t)
	rsaPriv, ok := priv["rsa2048"].(*rsa.PrivateKey)
	require.True(t, ok)

	// The bytes an attacker would use as the HMAC secret, and the bytes a
	// careless caller might hand to Validate as the verification key.
	der, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	require.NoError(t, err)

	payload := map[string]any{
		"iss": parityIssuer,
		"jti": "j",
		"aud": "aud-one",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	opts := &ValidationOptions{EXP: time.Second, NBF: time.Second}

	allowed := map[string]SigningMethod{
		"RS256": SigningMethodRS256, "RS384": SigningMethodRS384, "RS512": SigningMethodRS512,
		"PS256": SigningMethodPS256, "PS384": SigningMethodPS384, "PS512": SigningMethodPS512,
		"ES256": SigningMethodES256, "ES384": SigningMethodES384, "ES512": SigningMethodES512,
	}

	keys := map[string]any{"raw der bytes": der, "parsed rsa public key": pub["rsa2048"]}

	for _, alg := range []string{"HS256", "HS384", "HS512", "none"} {
		token, err := ParseToken(forgeCompact(t, alg, payload, der))
		require.NoError(t, err, "%s token should parse", alg)

		for keyName, key := range keys {
			for methodName, method := range allowed {
				require.Error(t, token.Validate(key, method, opts),
					"an alg:%s token must not verify as %s with the %s", alg, methodName, keyName)
			}
		}
	}

	// Positive control: without this the assertions above would pass even if
	// Validate rejected everything.
	claims := Claims{}
	claims.SetIssuer(parityIssuer)
	claims.SetJWTID("j")
	claims.SetAudience("aud-one")
	claims.SetIssuedAt(time.Now().Add(-time.Minute))
	claims.SetExpiration(time.Now().Add(time.Hour))
	signed := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, claims)
	signed.Header[ClaimKeyID] = parityIssuer + "/key1"
	raw, err := signed.SignedString(rsaPriv)
	require.NoError(t, err)

	genuine, err := ParseToken(raw)
	require.NoError(t, err)
	require.NoError(t, genuine.Validate(pub["rsa2048"], SigningMethodRS256, opts),
		"a correctly signed RS256 token must still verify")
}

// TestLeewayBoundaryIsInclusive pins the comparison semantics validateTime was
// written to preserve. The previous implementation accepted exp exactly
// exp+leeway away and rejected nbf exactly nbf-leeway away; the underlying
// library's defaults do the opposite at those two instants, which is why the
// comparison is hand-rolled at all.
func TestLeewayBoundaryIsInclusive(t *testing.T) {
	priv, pub := loadParityKeys(t)
	rsaPriv, ok := priv["rsa2048"].(*rsa.PrivateKey)
	require.True(t, ok)

	now := time.Unix(1700000000, 0).UTC()
	withClock(t, now)
	const leeway = time.Second
	opts := &ValidationOptions{EXP: leeway, NBF: leeway}

	sign := func(mutate func(Claims)) Token {
		t.Helper()
		claims := Claims{}
		claims.SetIssuer(parityIssuer)
		claims.SetJWTID("j")
		claims.SetAudience("aud-one")
		claims.SetIssuedAt(now.Add(-time.Minute))
		claims.SetExpiration(now.Add(time.Hour))
		mutate(claims)

		signed := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, claims)
		signed.Header[ClaimKeyID] = parityIssuer + "/key1"
		raw, err := signed.SignedString(rsaPriv)
		require.NoError(t, err)

		token, err := ParseToken(raw)
		require.NoError(t, err)
		return token
	}

	// exp == now - leeway is the inclusive boundary: still valid, because the
	// comparison is now.After(exp+leeway). The library default would call this
	// expired.
	require.NoError(t, sign(func(c Claims) { c.SetExpiration(now.Add(-leeway)) }).
		Validate(pub["rsa2048"], SigningMethodRS256, opts),
		"exp exactly at now-leeway must be accepted")

	// One second earlier it is expired.
	require.Error(t, sign(func(c Claims) { c.SetExpiration(now.Add(-leeway - time.Second)) }).
		Validate(pub["rsa2048"], SigningMethodRS256, opts),
		"exp beyond the leeway must be rejected")

	// nbf == now + leeway is the other inclusive boundary: not yet valid,
	// because the comparison is !now.After(nbf-leeway). The library default
	// would accept this.
	require.Error(t, sign(func(c Claims) { c.SetNotBefore(now.Add(leeway)) }).
		Validate(pub["rsa2048"], SigningMethodRS256, opts),
		"nbf exactly at now+leeway must be rejected")

	// One second earlier it is valid.
	require.NoError(t, sign(func(c Claims) { c.SetNotBefore(now.Add(leeway - time.Second)) }).
		Validate(pub["rsa2048"], SigningMethodRS256, opts),
		"nbf inside the leeway must be accepted")
}
