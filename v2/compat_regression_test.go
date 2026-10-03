package asap

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file holds regression guards for defects found while porting off jose.
// Each one is a behaviour the old implementation had and the port must keep.

// TestClaimsAudienceNormalisation pins the claim-normalisation rules the
// previous implementation applied to "aud".
func TestClaimsAudienceNormalisation(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want []string
		ok   bool
	}{
		{"single string", "aud-one", []string{"aud-one"}, true},
		{"string slice", []string{"aud-one", "aud-two"}, []string{"aud-one", "aud-two"}, true},
		{"json array", []any{"aud-one", "aud-two"}, []string{"aud-one", "aud-two"}, true},
		{"single element json array", []any{"aud-one"}, []string{"aud-one"}, true},
		{"empty json array", []any{}, nil, false},
		{"array with a non string element", []any{"aud-one", 5}, nil, false},
		{"number", 5, nil, false},
		{"absent", nil, nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := Claims{}
			if c.in != nil {
				claims.Set(ClaimAudience, c.in)
			}
			got, ok := claims.Audience()
			require.Equal(t, c.ok, ok)
			require.Equal(t, c.want, got)
		})
	}
}

// TestAudienceValidatorArrayClaim guards against a port bug where a JSON array
// audience produced no audiences at all, so a multi-audience token was rejected
// even though it listed an allowed audience. The claim is taken off the wire,
// because an in-memory []string audience never went through the broken path.
func TestAudienceValidatorArrayClaim(t *testing.T) {
	priv, _ := loadParityKeys(t)

	provisioner := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, []string{"aud-one", "aud-two"}, SigningMethodRS256)
	minted, err := provisioner.Provision()
	require.NoError(t, err)
	raw, err := minted.Serialize(priv["rsa2048"])
	require.NoError(t, err)

	parsed, err := ParseToken(string(raw))
	require.NoError(t, err)
	require.IsType(t, []any{}, parsed.Claims().Get(ClaimAudience))

	require.NoError(t, NewAllowedAudienceValidator("aud-one").Validate(parsed))
	require.NoError(t, NewAllowedAudienceValidator("aud-two").Validate(parsed))
	require.Error(t, NewAllowedAudienceValidator("aud-three").Validate(parsed))
}

// TestMultiAudienceTokenPassesDocumentedValidation is the end-to-end form of the
// same bug, following the documented provision -> serialize -> parse -> validate
// path from the README.
func TestMultiAudienceTokenPassesDocumentedValidation(t *testing.T) {
	priv, pub := loadParityKeys(t)

	provisioner := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, []string{"aud-one", "aud-two"}, SigningMethodRS256)
	token, err := provisioner.Provision()
	require.NoError(t, err)

	raw, err := token.Serialize(priv["rsa2048"])
	require.NoError(t, err)

	parsed, err := ParseToken(string(raw))
	require.NoError(t, err)

	chain := NewValidatorChain(
		DefaultValidator,
		NewSignatureValidator(&fixtureFetcher{value: pub["rsa2048"]}),
		NewAllowedAudienceValidator("aud-one"),
	)
	require.NoError(t, chain.Validate(parsed))
}

// TestProvisionedTokensAreNotCacheable guards the cache-key contract: only
// tokens read off the wire carry a cache key. A freshly minted token has no
// serialized form yet, and the previous implementation did not expose a cache
// key on those tokens either; doing so would make every minted token collide in
// a caching validator.
func TestProvisionedTokensAreNotCacheable(t *testing.T) {
	priv, _ := loadParityKeys(t)

	provisioned, err := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, []string{"aud-one"}, SigningMethodRS256).Provision()
	require.NoError(t, err)
	_, ok := provisioned.(CacheableKeyer)
	require.False(t, ok, "a freshly minted token must not satisfy CacheableKeyer")

	raw, err := provisioned.Serialize(priv["rsa2048"])
	require.NoError(t, err)

	parsed, err := ParseToken(string(raw))
	require.NoError(t, err)
	keyer, ok := parsed.(CacheableKeyer)
	require.True(t, ok, "a parsed token must satisfy CacheableKeyer")
	require.Equal(t, string(raw), keyer.CacheKey())
}

// TestNonObjectPayloadIsRejected matches the previous implementation, which
// refused any payload that was not a claims object, including the JSON literal
// null.
func TestNonObjectPayloadIsRejected(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	compact := func(payload string) string {
		return header + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".AAAA"
	}

	for _, payload := range []string{"null", `[1,2]`, `"str"`, "5", "true"} {
		_, err := ParseToken(compact(payload))
		require.Error(t, err, "payload %s must be rejected", payload)
	}

	token, err := ParseToken(compact(`{}`))
	require.NoError(t, err, "an empty object is still a claims object")
	require.NotNil(t, token.Claims())
	require.Empty(t, token.Claims())
}

// TestHeaderHas guards the accessor set of Header against regressing.
func TestHeaderHas(t *testing.T) {
	header := Header{ClaimKeyID: "iss/key"}
	require.True(t, header.Has(ClaimKeyID))
	require.False(t, header.Has(ClaimAlgorithm))

	var absent Header
	require.False(t, absent.Has(ClaimKeyID))
	require.Nil(t, absent.Get(ClaimKeyID))
}
