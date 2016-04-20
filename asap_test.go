package asap

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

const minValidBits = 768

var (
	asap       *ASAP
	keyID      string
	serviceID  string
	privateKey *rsa.PrivateKey
)

func beforeEach() {
	serviceID = "service"
	keyID = serviceID + "/"
	privateKey, _ = rsa.GenerateKey(rand.Reader, minValidBits)
	asap = NewASAP(keyID, "service", []string{"service"})
}

func TestSignWorksWithValidKey(t *testing.T) {
	beforeEach()
	if _, err := asap.Sign(serviceID, privateKey); err != nil {
		t.Errorf("Failed to sign: %+v", err)
	}
}

func TestSignFailsWithNilKey(t *testing.T) {
	beforeEach()
	privateKey = nil
	if _, err := asap.Sign(serviceID, privateKey); err == nil {
		t.Errorf("Did not fail to sign: %+v", err)
	}
}

func TestSignFailsWithInvalidKey(t *testing.T) {
	beforeEach()
	privateKey.D = big.NewInt(0) // Break the key
	if _, err := asap.Sign(serviceID, privateKey); err != nil {
		t.Errorf("Did not fail to sign: %+v", err)
	}
}

func TestSignParseValidate(t *testing.T) {
	beforeEach()
	token, _ := asap.Sign(serviceID, privateKey)
	jwt, _ := asap.Parse(token)
	if err := asap.Validate(jwt, &privateKey.PublicKey); err != nil {
		t.Errorf("Failed to verify token: %+v", err)
	}
}
