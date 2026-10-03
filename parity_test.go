package asap

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This file replays the behaviour of the jose-based implementation, frozen in
// testdata/parity by tools/paritygen before the migration. jose cannot run on
// Go 1.27, so these fixtures are the only oracle available for "did the wire
// format and the validation verdicts stay the same?".

const (
	parityDir    = "testdata/parity"
	parityIssuer = "svc-issuer"
)

type parityKey struct {
	Alg        string `json:"alg"`
	PrivatePEM string `json:"privatePEM"`
	PublicPEM  string `json:"publicPEM"`
}

type parityMeta struct {
	Anchor string `json:"anchor"`
}

type parityWireCase struct {
	Name     string          `json:"name"`
	Token    string          `json:"token"`
	MintedBy string          `json:"mintedBy"`
	ParseOK  bool            `json:"joseParseOK"`
	ParseErr string          `json:"joseParseErr"`
	Header   json.RawMessage `json:"joseHeader"`
	Claims   json.RawMessage `json:"joseClaims"`
	Note     string          `json:"note"`
}

type parityValidationCase struct {
	Name        string `json:"name"`
	Token       string `json:"token"`
	Method      string `json:"method"`
	Key         string `json:"key"`
	DefaultOK   bool   `json:"asapDefaultOK"`
	DefaultErr  string `json:"asapDefaultErr"`
	SigOK       bool   `json:"asapSigOK"`
	SigErr      string `json:"asapSigErr"`
	AudienceOK  bool   `json:"asapAudienceOK"`
	RolesOK     bool   `json:"asapRolesOK"`
	ExpectValid bool   `json:"expectValid"`
	Note        string `json:"note"`
}

// parityKeyForAlg maps a fixture algorithm to the key material it was minted
// with, mirroring the generator.
var parityKeyForAlg = map[string]string{
	"RS256": "rsa2048", "RS384": "rsa2048", "RS512": "rsa2048",
	"PS256": "rsa2048", "PS384": "rsa2048", "PS512": "rsa2048",
	"ES256": "ec256", "ES384": "ec384", "ES512": "ec512",
}

func loadParityJSON[T any](t *testing.T, name string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parityDir, name))
	require.NoError(t, err, "fixture %s is missing; regenerate with tools/paritygen", name)
	var v T
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

func loadParityKeys(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	keys := loadParityJSON[map[string]parityKey](t, "keys.json")
	priv := map[string]any{}
	pub := map[string]any{}
	for name, k := range keys {
		p, err := NewPrivateKey([]byte(k.PrivatePEM))
		require.NoError(t, err, "private key %s", name)
		priv[name] = p
		q, err := NewPublicKey([]byte(k.PublicPEM))
		require.NoError(t, err, "public key %s", name)
		pub[name] = q
	}
	return priv, pub
}

func decodeParityObject(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func decodeParitySegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// parityECDSAAlgs are the algorithms jose v0.9.2 signed with ASN.1/DER
// encoded ECDSA signatures instead of the raw R||S concatenation RFC 7518
// section 3.4 requires. See TestParityECDSAEncoding: this package deliberately
// does not reproduce that defect.
var parityECDSAAlgs = map[string]bool{"ES256": true, "ES384": true, "ES512": true}

// TestParityWire checks that every token jose accepted or rejected is treated
// identically, that the claim set and protected header survive parsing
// unchanged, and that a signature jose produced is accepted by the new stack.
func TestParityWire(t *testing.T) {
	priv, pub := loadParityKeys(t)
	cases := loadParityJSON[[]parityWireCase](t, "wire.json")
	require.NotEmpty(t, cases)

	// The wire fixtures were minted against a fixed 2024 epoch. Pin the clock
	// there so the lifetime check in Validate is deterministic.
	withClock(t, time.Unix(1704067200, 0).UTC())

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			tok, err := ParseToken(c.Token)
			if !c.ParseOK {
				require.Error(t, err, "jose rejected this token at parse time: %s", c.ParseErr)
				return
			}
			require.NoError(t, err)

			if c.Header != nil {
				require.Equal(t, decodeParityObject(t, c.Header), map[string]any(tok.Protected()))
			}
			if c.Claims != nil {
				require.Equal(t, decodeParityObject(t, c.Claims), map[string]any(tok.Claims()))
			}

			if c.MintedBy != "jose" {
				return
			}

			alg, ok := tok.Protected().Get(ClaimAlgorithm).(string)
			require.True(t, ok)
			keyName, ok := parityKeyForAlg[alg]
			require.True(t, ok, "fixture uses an algorithm the matrix does not know: %s", alg)
			method, ok := signingMethodMap[alg]
			require.True(t, ok)

			// Re-signing has to round-trip through our own parser.
			resigned, err := tok.Serialize(priv[keyName])
			require.NoError(t, err)
			reparsed, err := ParseToken(string(resigned))
			require.NoError(t, err)
			require.Equal(t, map[string]any(tok.Claims()), map[string]any(reparsed.Claims()))

			if parityECDSAAlgs[alg] {
				// jose's ECDSA signatures are DER encoded and are rejected by
				// compliant verifiers; TestParityECDSAEncoding owns this case.
				require.Error(t, tok.Validate(pub[keyName], method, &ValidationOptions{EXP: time.Second, NBF: time.Second}),
					"a DER encoded ECDSA signature must not verify under RFC 7518")
				return
			}

			// jose signed it; the new stack has to verify it.
			require.NoError(t, tok.Validate(pub[keyName], method, &ValidationOptions{EXP: time.Second, NBF: time.Second}),
				"golang-jwt did not verify a jose-minted %s signature", alg)
		})
	}
}

// ecdsaHalfSize is the byte width of one half of a raw RFC 7518 ECDSA
// signature for each supported curve.
var ecdsaHalfSize = map[string]int{"ES256": 32, "ES384": 48, "ES512": 66}

// TestParityECDSAEncoding pins the one intentional behavioural divergence the
// oracle uncovered. jose v0.9.2 signed ES256/ES384/ES512 with
// asn1.Marshal({r,s}), so the signature segment was a DER SEQUENCE. RFC 7518
// section 3.4 requires the raw R||S concatenation instead, which means every
// ECDSA token the old stack minted was rejected by compliant peers.
//
// This package emits the compliant form. Old ECDSA tokens therefore fail to
// verify, and ECDSA tokens minted here will not verify under a jose-based peer.
// Deployments that chose an ES* algorithm have to re-issue tokens and upgrade
// both ends together; the RS256 default is unaffected.
func TestParityECDSAEncoding(t *testing.T) {
	priv, pub := loadParityKeys(t)
	withClock(t, time.Unix(1704067200, 0).UTC())

	byAlg := map[string]parityWireCase{}
	for _, c := range loadParityJSON[[]parityWireCase](t, "wire.json") {
		if c.MintedBy != "jose" || len(c.Header) == 0 {
			continue
		}
		var header map[string]any
		require.NoError(t, json.Unmarshal(c.Header, &header))
		alg, ok := header[ClaimAlgorithm].(string)
		if !ok || !parityECDSAAlgs[alg] {
			continue
		}
		if _, seen := byAlg[alg]; !seen {
			byAlg[alg] = c
		}
	}

	for alg, keyName := range map[string]string{"ES256": "ec256", "ES384": "ec384", "ES512": "ec512"} {
		c, ok := byAlg[alg]
		require.True(t, ok, "no jose-minted %s fixture", alg)
		method := signingMethodMap[alg]

		joseSig := fixtureSignature(t, c.Token)
		require.Equal(t, byte(0x30), joseSig[0],
			"%s: expected jose's DER SEQUENCE tag; the fixture no longer evidences the divergence", alg)

		joseToken, err := ParseToken(c.Token)
		require.NoError(t, err)
		require.Error(t, joseToken.Validate(pub[keyName], method, &ValidationOptions{EXP: time.Second, NBF: time.Second}),
			"%s: a DER encoded signature must be rejected", alg)

		// Our own tokens use the raw R||S form and must verify.
		p := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, []string{"aud-one"}, method)
		ours, err := p.Provision()
		require.NoError(t, err)
		raw, err := ours.Serialize(priv[keyName])
		require.NoError(t, err)

		ourSig := fixtureSignature(t, string(raw))
		require.Equal(t, 2*ecdsaHalfSize[alg], len(ourSig),
			"%s: signature must be the raw R||S concatenation", alg)

		reparsed, err := ParseToken(string(raw))
		require.NoError(t, err)
		require.NoError(t, reparsed.Validate(pub[keyName], method, &ValidationOptions{EXP: time.Second, NBF: time.Second}),
			"%s: our own compliant signature must verify", alg)
	}
}

func fixtureSignature(t *testing.T, token string) []byte {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	return raw
}

// TestParityValidation replays the verdicts of the real DefaultValidator and
// SignatureValidator on jose-minted tokens, with the clock pinned to the
// anchor the fixtures were generated at.
func TestParityValidation(t *testing.T) {
	_, pub := loadParityKeys(t)
	anchor, err := time.Parse(time.RFC3339, loadParityJSON[parityMeta](t, "meta.json").Anchor)
	require.NoError(t, err)

	cases := loadParityJSON[[]parityValidationCase](t, "validation.json")
	require.NotEmpty(t, cases)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			withClock(t, anchor)

			tok, err := ParseToken(c.Token)
			require.NoError(t, err)

			err = DefaultValidator.Validate(tok)
			require.Equal(t, c.DefaultOK, err == nil, "DefaultValidator verdict changed (%s): %v", c.Note, err)
			requireParityError(t, c.DefaultErr, err)

			// Validators that consume the parsed claim shapes, not just the
			// individual claim values.
			err = NewAllowedAudienceValidator("aud-one").Validate(tok)
			require.Equal(t, c.AudienceOK, err == nil, "audience verdict changed (%s): %v", c.Note, err)

			err = NewAllowedClaimValuesValidator("roles", "writer").Validate(tok)
			require.Equal(t, c.RolesOK, err == nil, "array claim verdict changed (%s): %v", c.Note, err)

			if c.Method == "" {
				return
			}

			err = NewSignatureValidator(&fixtureFetcher{value: pub[c.Key]}).Validate(tok)
			require.Equal(t, c.SigOK, err == nil, "SignatureValidator verdict changed (%s): %v", c.Note, err)
			requireParityError(t, c.SigErr, err)
		})
	}
}

// asapOwnedErrorPrefixes are messages produced by this package's own
// validators. Their text is part of the compatibility contract and must not
// drift. Failures raised inside the JWT library are compared by verdict only,
// because the library words them differently.
var asapOwnedErrorPrefixes = []string{
	"Missing claim ",
	"Claim ",
	"Missing algorithm",
	"Unsupported algorithm: ",
	"No given audience values ",
	"the KeyID ",
	"missing or invalid kid",
	"Missing or invalid key id",
	"Missing or invalid issued at time",
	"IssuedAt time ",
	"Protected header is nil",
	"Missing the kid header",
	"kid header value is not a string",
	"token is expired",
	"token is not yet valid",
}

func requireParityError(t *testing.T, want string, got error) {
	t.Helper()
	if want == "" {
		require.NoError(t, got)
		return
	}
	gotStr := ""
	if got != nil {
		gotStr = got.Error()
	}
	for _, prefix := range asapOwnedErrorPrefixes {
		if strings.HasPrefix(want, prefix) {
			require.Equal(t, want, gotStr)
			return
		}
	}
	// Library-owned message: the accept/reject verdict is asserted by the
	// caller; here we only require that some error was reported.
	require.NotEmpty(t, gotStr)
}

// TestParityMinting pins the wire shape this package produces. jose collapsed a
// single audience to a bare string and only used a list for two or more; if
// that ever regresses, every single-audience ASAP token in flight changes
// shape.
func TestParityMinting(t *testing.T) {
	priv, pub := loadParityKeys(t)
	rsa := priv["rsa2048"]

	issued := time.Unix(1704067200, 0).UTC()
	withClock(t, issued)

	newToken := func(audience []string) (map[string]any, string) {
		t.Helper()
		p := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, audience, SigningMethodRS256)
		tok, err := p.Provision()
		require.NoError(t, err)
		raw, err := tok.Serialize(rsa)
		require.NoError(t, err)

		parts := strings.Split(string(raw), ".")
		require.Len(t, parts, 3)
		return decodeParitySegment(t, parts[1]), string(raw)
	}

	t.Run("single audience stays a bare string", func(t *testing.T) {
		claims, raw := newToken([]string{"aud-one"})
		require.Equal(t, "aud-one", claims["aud"])
		require.IsType(t, "", claims["aud"])

		parsed, err := ParseToken(raw)
		require.NoError(t, err)
		require.NoError(t, parsed.Validate(pub["rsa2048"], SigningMethodRS256, &ValidationOptions{EXP: time.Second, NBF: time.Second}))
	})

	t.Run("multiple audiences become a list", func(t *testing.T) {
		claims, _ := newToken([]string{"aud-one", "aud-two"})
		require.Equal(t, []any{"aud-one", "aud-two"}, claims["aud"])
	})

	t.Run("empty audience serialises as null", func(t *testing.T) {
		// jose emitted {"aud":null} for SetAudience() with no arguments; the key
		// is present and null, not absent and not an empty list.
		claims, _ := newToken(nil)
		v, present := claims["aud"]
		require.True(t, present, "the aud key must be present")
		require.Nil(t, v)
	})

	t.Run("registered claims and header match the frozen shape", func(t *testing.T) {
		issued := time.Unix(1704067200, 0).UTC()
		p := NewProvisioner(parityIssuer+"/key1", time.Hour, parityIssuer, []string{"aud-one"}, SigningMethodRS256)
		tok, err := p.Provision()
		require.NoError(t, err)
		raw, err := tok.Serialize(rsa)
		require.NoError(t, err)

		parts := strings.Split(string(raw), ".")
		require.Len(t, parts, 3)
		header := decodeParitySegment(t, parts[0])
		claims := decodeParitySegment(t, parts[1])

		require.Equal(t, map[string]any{
			ClaimAlgorithm: "RS256",
			ClaimKeyID:     parityIssuer + "/key1",
			"typ":          "JWT",
		}, header)
		require.Equal(t, parityIssuer, claims[ClaimIssuer])
		require.Equal(t, float64(issued.Unix()), claims[ClaimIssuedAt], "iat must be integer epoch seconds")
		require.Equal(t, float64(issued.Add(time.Hour).Unix()), claims[ClaimExpiration], "exp must be integer epoch seconds")

		jti, ok := claims[ClaimTokenID].(string)
		require.True(t, ok)
		_, err = uuid.Parse(jti)
		require.NoError(t, err)
	})
}

// TestParityFixtureCoverage guards the oracle itself: a fixture file that
// silently loses an algorithm would otherwise make the suite pass while
// covering less.
func TestParityFixtureCoverage(t *testing.T) {
	cases := loadParityJSON[[]parityWireCase](t, "wire.json")
	seen := map[string]bool{}
	for _, c := range cases {
		if len(c.Header) == 0 {
			continue
		}
		var header map[string]any
		require.NoError(t, json.Unmarshal(c.Header, &header))
		if alg, ok := header[ClaimAlgorithm].(string); ok {
			seen[alg] = true
		}
	}
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "none", "HS256"} {
		require.True(t, seen[alg], "wire fixtures no longer cover algorithm %s", alg)
	}

	validation := loadParityJSON[[]parityValidationCase](t, "validation.json")
	var requiredClaimsCovered, kidCovered, timeCovered, signatureCovered bool
	var audienceAccepted, audienceRejected bool
	for _, c := range validation {
		switch {
		case strings.HasPrefix(c.Name, "missing_"):
			requiredClaimsCovered = true
		case strings.HasPrefix(c.Name, "kid_"):
			kidCovered = true
		case strings.HasPrefix(c.Name, "expired_"), strings.HasPrefix(c.Name, "not_before_"), strings.HasPrefix(c.Name, "lifetime_"):
			timeCovered = true
		case c.Name == "signed_by_wrong_key", c.Name == "payload_tampered":
			signatureCovered = true
		}
		if c.AudienceOK {
			audienceAccepted = true
		} else {
			audienceRejected = true
		}
	}
	require.True(t, requiredClaimsCovered, "validation fixtures no longer cover required claims")
	require.True(t, kidCovered, "validation fixtures no longer cover kid rules")
	require.True(t, timeCovered, "validation fixtures no longer cover token lifetime")
	require.True(t, signatureCovered, "validation fixtures no longer cover signature failures")
	require.True(t, audienceAccepted && audienceRejected,
		"the audience oracle no longer discriminates between an allowed and a rejected audience")
}
