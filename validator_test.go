package asap

import (
	"fmt"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func TestValidatorChainRunsAll(t *testing.T) {
	var counter = 0
	var validator = func(Token) error {
		counter++
		return nil
	}
	var v = NewValidatorChain(validatorFunc(validator), validatorFunc(validator))
	var e = v.Validate(nil)
	if e != nil {
		t.Fatalf("Error testing validator chain: %s", e)
	}
	if counter != 2 {
		t.Fatalf("Expected 2 validator runs but saw %d", counter)
	}
}

func TestValidatorChainExitsOnFirstFailure(t *testing.T) {
	var counter = 0
	var countValidator = func(Token) error {
		counter++
		return nil
	}
	var err = fmt.Errorf("")
	var errValidator = func(Token) error { return err }
	var v = NewValidatorChain(validatorFunc(countValidator), validatorFunc(errValidator), validatorFunc(countValidator))
	var e = v.Validate(nil)
	if e != err {
		t.Fatalf("Expected the test error but got: %s", e)
	}
	if counter != 1 {
		t.Fatalf("Expected 1 validator run but saw %d", counter)
	}
}

func TestClaimsValidatorFound(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewRequiredClaimsValidator("TEST")
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the claim validator to pass but got %s", e)
	}
}

func TestClaimsValidatorMissing(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewRequiredClaimsValidator("TEST2")
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the claim validator to fail but it didn't")
	}
}

func TestStringsValidatorMatch(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedStringsValidator("TEST", "TEST")
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the strings validator to pass but got %s", e)
	}
}

func TestStringsValidatorNoMatch(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedStringsValidator("TEST", "TEST2")
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the strings validator to fail but it didn't")
	}
}

func TestStringsValidatorMissing(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedStringsValidator("TEST2", "TEST2")
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the strings validator to fail but it didn't")
	}
}

func TestAudienceValidatorMatch(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetAudience("TEST2")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedAudienceValidator("TEST", "TEST2")
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the audience validator to pass but got %s", e)
	}
}

func TestAudienceValidatorNoMatch(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetAudience("TEST3")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedStringsValidator("TEST", "TEST2")
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the audience validator to fail but it didn't")
	}
}

func TestAudienceValidatorMissing(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = NewAllowedAudienceValidator("TEST", "TEST2")
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the audience validator to fail but it didn't")
	}
}

func TestKidValidatorMatch(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuer("TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	var v = KidValidator
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the kid validator to pass but got %s", e)
	}
}

func TestKidValidatorKidMissingIssuer(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuer("TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.(jws.JWS).Protected().Set(ClaimKeyID, "/TEST")
	var v = KidValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the kid validator to fail but it didn't")
	}
}

func TestKidValidatorKidMissing(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuer("TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = KidValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the kid validator to fail but it didn't")
	}
}

func TestKidValidatorInvalidPathSegments(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuer("TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST/./..")
	var v = KidValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the kid validator to fail but it didn't")
	}
}

func TestKidValidatorInvalidCharacters(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuer("TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST/\\")
	var v = KidValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the kid validator to fail but it didn't")
	}
}

func TestAlgorithmValidatorSupported(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = AlgorithmValidator
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the algorithm validator to pass but got %s", e)
	}
}

func TestAlgorithmValidatorUnsupported(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.Unsecured)
	var v = AlgorithmValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the algorithm validator to fail but it didn't")
	}
}

func TestExpirationValidatorShortLived(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuedAt(time.Now())
	claims.SetExpiration(time.Now().Add(time.Hour))
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = ExpirationValidator
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("Expected the expiration validator to pass but got %s", e)
	}
}

func TestExpirationValidatorMissingIssuedAt(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = ExpirationValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the expiration validator to fail but it didn't")
	}
}

func TestExpirationValidatorLongLived(t *testing.T) {
	var claims = jws.Claims{}
	claims.Set("TEST", "TEST")
	claims.SetIssuedAt(time.Now())
	claims.SetExpiration(time.Now().Add(5 * time.Hour))
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	var v = ExpirationValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("Expected the expiration validator to fail but it didn't")
	}
}

func TestSignatureValidator(t *testing.T) {
	var token, _ = NewProvisioner("TEST/TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256).Provision()
	var privKey, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var pubKey, _ = NewPublicKey([]byte(publicKey))
	var b, _ = token.Serialize(privKey)
	var v = NewSignatureValidator(&fixtureFetcher{value: pubKey})
	var incoming, _ = ParseToken(string(b))
	var e = v.Validate(incoming)
	if e != nil {
		t.Fatalf("Failed to validate a properly signed token.")
	}

	v = NewSignatureValidator(&fixtureFetcher{value: privKey})
	e = v.Validate(incoming)
	if e == nil {
		t.Fatalf("Failed to error on an invalid signature.")
	}
}

func TestSignatureValidatorInvalidAlgorithm(t *testing.T) {
	// CSECHELP-348 -- the following is not a real token
	token := `eyJhbGciOiJub25lIiwia2lkIjoiaXMvazEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJ0YXJnZXRfc2VydmljZTEiLCJleHAiOjE2MzcyODMxMjMsImlhdCI6MTYzNzI4MjUyMywiaXNzIjoiaXMiLCJqdGkiOiJhM2M1NmMxNy1jNGFkLTRlZDQtYjYzYS0yNWNmNGU4ZTg2YTQifQ.HY86A2QK9NadmPj8-6kU2AFoHu_fiwdpbmy8ibZclwUU-HlkxYwn2BMhS0cuOIRT1aPehLGo_LY4kD1WzngVldWViISKVQY8lBCAzlijVXH_kS1zyLitErFdPVMq6LgrgLsZvk_o387oI7yz_B_xkuOD2anzF7gR-D_tP2S4VLF6PLLCIvcu5MRQ7d5k9PB4DyLE7f5FIFKwN8HEtjZP3LXj8-zZUhCVRqVs1c3TLRC4WbH9RX5SmE-U2vqWfK1vkUxb723fzdkf39VtJP3QBnVj8gQTrYUDkqRkLxDahp1CxWdlEZAln7K3MYOzK9Oc4l3-SuxwA5Zf9A7JzxRCgg` // nolint: gosec
	v := NewSignatureValidator(&fixtureFetcher{value: ""})
	incoming, _ := ParseToken(token)
	err := v.Validate(incoming)
	if err == nil {
		t.Fatalf("Failed to return error for invalid signature method.")
	}

	if err.Error() != "Unsupported algorithm: none" {
		t.Fatalf("Returned incorrect error message")
	}
}

// DefaultValidator tests

func TestIssRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveIssuer()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("JWT with missing iss should not be allowed")
	}
}

func TestExpRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveExpiration()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("JWT with missing exp should not be allowed")
	}
}

func TestIatRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveIssuedAt()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("JWT with missing iat should not be allowed")
	}
}

func TestAudRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveAudience()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("JWT with missing aud should not be allowed")
	}
}

func TestJtiRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveJWTID()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e == nil {
		t.Fatal("JWT with missing jti should not be allowed")
	}
}

func TestSubNotRequired(t *testing.T) {
	var claims = jws.Claims{}
	var token = jws.NewJWT(claims, crypto.SigningMethodRS256)
	token.Claims().SetIssuer("TEST")
	token.Claims().SetIssuedAt(time.Now())
	token.Claims().SetExpiration(time.Now().Add(time.Hour))
	token.Claims().SetAudience("TEST")
	token.Claims().SetJWTID("TEST")
	token.(jws.JWS).Protected().Set(ClaimKeyID, "TEST/TEST")
	token.Claims().RemoveSubject()
	var v = DefaultValidator
	var e = v.Validate(token)
	if e != nil {
		t.Fatalf("JWT should not require sub and should infer it from iss: %s", e)
	}
}

// --- NewAllowedClaimValuesValidator tests ---

func TestAllowedClaimValuesValidator_ScalarMatch(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("iss", "micros/foo")
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("iss", "micros/foo", "micros/bar")
	if err := v.Validate(token); err != nil {
		t.Fatalf("expected scalar match to pass, got: %s", err)
	}
}

func TestAllowedClaimValuesValidator_ScalarNoMatch(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("iss", "micros/other")
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("iss", "micros/foo", "micros/bar")
	if err := v.Validate(token); err == nil {
		t.Fatal("expected scalar no-match to fail, but it passed")
	}
}

func TestAllowedClaimValuesValidator_ArrayMatch(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("roles", []any{"reader", "writer"})
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer", "admin")
	if err := v.Validate(token); err != nil {
		t.Fatalf("expected array match to pass, got: %s", err)
	}
}

func TestAllowedClaimValuesValidator_ArrayNoMatch(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("roles", []any{"reader"})
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer", "admin")
	if err := v.Validate(token); err == nil {
		t.Fatal("expected array no-match to fail, but it passed")
	}
}

func TestAllowedClaimValuesValidator_ArrayEmpty(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("roles", []any{})
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer")
	if err := v.Validate(token); err == nil {
		t.Fatal("expected empty array to fail, but it passed")
	}
}

func TestAllowedClaimValuesValidator_MissingClaim(t *testing.T) {
	claims := jws.Claims{}
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer")
	if err := v.Validate(token); err == nil {
		t.Fatal("expected missing claim to fail, but it passed")
	}
}

func TestAllowedClaimValuesValidator_UnsupportedType(t *testing.T) {
	claims := jws.Claims{}
	claims.Set("roles", 12345) // integer, not string or []interface{}
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer")
	if err := v.Validate(token); err == nil {
		t.Fatal("expected unsupported type to fail, but it passed")
	}
}

func TestAllowedClaimValuesValidator_ArrayWithNonStringElements(t *testing.T) {
	claims := jws.Claims{}
	// Mix of non-string elements and a matching string — non-strings should be skipped
	claims.Set("roles", []any{42, true, "writer"})
	token := jws.NewJWT(claims, crypto.SigningMethodRS256)
	v := NewAllowedClaimValuesValidator("roles", "writer")
	if err := v.Validate(token); err != nil {
		t.Fatalf("expected match despite non-string elements, got: %s", err)
	}
}
