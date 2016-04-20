package asap

import (
	"bitbucket.org/drpotato_atlassian/go-asap/keyprovider"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"
)

const minValidBits = 768

var (
	asap       *ASAP
	keyID      string
	kp         *keyprovider.MockKeyProvider
	serviceID  string
	privateKey *rsa.PrivateKey
)

func beforeEach() {
	serviceID = "service"
	keyID = serviceID + "/"
	privateKey, _ = rsa.GenerateKey(rand.Reader, minValidBits)
	kp = &keyprovider.MockKeyProvider{
		PublicKeys: map[string]*rsa.PublicKey{
			keyID: &privateKey.PublicKey,
		},
	}
	asap = NewASAP(keyID, "service", []string{"service"}, kp)
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
	kp.Err = errors.New("")
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

func TestSignVerify(t *testing.T) {
	beforeEach()
	token, _ := asap.Sign(serviceID, privateKey)
	if err := asap.Verify(token); err != nil {
		t.Errorf("Failed to verify token: %+v", err)
	}
}
