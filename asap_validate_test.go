package asap

import (
	"crypto/rsa"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
	"testing"
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
