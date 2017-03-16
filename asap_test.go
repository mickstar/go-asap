package asap

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
	"github.com/SermoDigital/jose/jws"
)

const minValidBits = 768

func setUp() (asap *ASAP, keyID string, serviceID string, privateKey *rsa.PrivateKey) {
	serviceID = "service"
	keyID = serviceID + "/"
	privateKey, _ = rsa.GenerateKey(rand.Reader, minValidBits)
	asap = NewASAP(keyID, serviceID, []string{"service"})
	return
}

func TestSignWorksWithValidKey(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	if _, err := asap.Sign(serviceID, privateKey); err != nil {
		t.Errorf("Failed to sign: %+v", err)
	}
}

func TestSignFailsWithInvalidKey(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	privateKey.D = big.NewInt(0) // Break the key
	privateKey.Precomputed.Dp = nil
	if _, err := asap.Sign(serviceID, privateKey); err == nil {
		t.Errorf("Did not fail to sign: %+v", err)
	}
}

func TestSignParseValidate(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	token, _ := asap.Sign(serviceID, privateKey)
	jwt, _ := asap.Parse(token)
	if err := asap.Validate(jwt, privateKey.Public()); err != nil {
		t.Errorf("Failed to verify token: %+v", err)
	}
}

func TestSignCustomClaims(t *testing.T) {
	asap, _, serviceID, privateKey := setUp()
	claims := jws.Claims{}
	claims.Set("custom", "value")
	token, _ := asap.SignCustomClaims(serviceID, claims, privateKey)
	jwt, _ := asap.Parse(token)
	if err := asap.Validate(jwt, &privateKey.PublicKey); err != nil {
		t.Errorf("Failed to verify token: %+v", err)
	}
	if jwt.Claims().Get("custom") != "value" {
		t.Error("Expected custom claim to be serialized and deserialized")
	}
}
