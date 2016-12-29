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
