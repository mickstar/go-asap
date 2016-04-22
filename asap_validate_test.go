package asap

import (
	"crypto/rsa"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
	"testing"
	"time"
)

var signingMethod = crypto.SigningMethodRS256

func setUpSigned(asap *ASAP, serviceID string, privateKey *rsa.PrivateKey) (signed []byte, token jwt.JWT) {
	signed, _ = asap.Sign(serviceID, privateKey)
	token, _ = asap.Parse(signed)
	return
}

func TestIssRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveIssuer()
	if err := asap.Validate(token, &privateKey.PublicKey); err == nil {
		t.Error("JWT with missing iss should not be allowed")
	}
}

func TestExpRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveExpiration()
	if err := asap.Validate(token, &privateKey.PublicKey); err == nil {
		t.Error("JWT with missing exp should not be allowed")
	}
}

func TestIatRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveIssuedAt()
	if err := asap.Validate(token, &privateKey.PublicKey); err == nil {
		t.Error("JWT with missing iat should not be allowed")
	}
}

func TestAudRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveAudience()
	if err := asap.Validate(token, &privateKey.PublicKey); err == nil {
		t.Error("JWT with missing aud should not be allowed")
	}
}

func TestJtiRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveJWTID()
	if err := asap.Validate(token, &privateKey.PublicKey); err == nil {
		t.Error("JWT with missing jti should not be allowed")
	}
}

func TestSubNotRequired(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	_, token := setUpSigned(asap, serviceID, privateKey)
	token.Claims().RemoveSubject()
	if err := asap.Validate(token, &privateKey.PublicKey); err != nil {
		t.Error("JWT should not require sub and should infer it from iss: " + err.Error())
	}
}

func TestUnsignedClaimRejected(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := asap.makeClaims(serviceID)
	signed, _ := asap.signClaims(claims, privateKey, crypto.Unsecured)
	parsed, _ := asap.Parse(signed)
	if err := asap.Validate(parsed, &privateKey.PublicKey); err == nil {
		t.Error("Unsigned JWT should not be allowed")
	}
}

func TestIssCheckedAgainstKid(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := asap.makeClaims(serviceID)
	claims.SetIssuer("malicious/")
	signed, _ := asap.signClaims(claims, privateKey, signingMethod)
	parsed, _ := asap.Parse(signed)
	if err := asap.Validate(parsed, &privateKey.PublicKey); err == nil {
		t.Error("Issuer shouldn't be allowed to make requests with another service's key")
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := asap.makeClaims(serviceID)
	claims.SetAudience("theotherone")
	signed, _ := asap.signClaims(claims, privateKey, signingMethod)
	parsed, _ := asap.Parse(signed)
	if err := asap.Validate(parsed, &privateKey.PublicKey); err == nil {
		t.Error("Requests must have the serviceID in their aud")
	}
}

func TestExpirationNotMoreThanAnHourAfterIssueAt(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := asap.makeClaims(serviceID)
	now := time.Now()
	claims.SetIssuedAt(float64(now.Unix()))
	claims.SetExpiration(float64(now.Add(time.Hour).Add(-time.Second).Unix()))
	signed, _ := asap.signClaims(claims, privateKey, signingMethod)
	parsed, _ := asap.Parse(signed)
	if err := asap.Validate(parsed, &privateKey.PublicKey); err != nil {
		t.Error(err)
	}
}
func TestExpirationMoreThanAnHourAfterIssuedAt(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := asap.makeClaims(serviceID)
	now := time.Now()
	claims.SetIssuedAt(float64(now.Unix()))
	claims.SetExpiration(float64(now.Add(time.Hour).Add(time.Second).Unix()))
	signed, _ := asap.signClaims(claims, privateKey, signingMethod)
	parsed, _ := asap.Parse(signed)
	if err := asap.Validate(parsed, &privateKey.PublicKey); err == nil {
		t.Fail()
	}
}
