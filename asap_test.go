package asap

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

const minValidBits = 768

func TestSignWorksWithValidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minValidBits)
	if err != nil {
		t.Error("Failed to generate a valid key, test broken: " + err.Error())
	}
	if _, err := Sign("subject", "keyID", "audience", key); err != nil {
		t.Errorf("Failed to sign: %+v", err)
	}
}

func TestSignFailsWithNilKey(t *testing.T) {
	if _, err := Sign("subject", "keyID", "audience", nil); err == nil {
		t.Errorf("Did not fail to sign: %+v", err)
	}
}

func TestSignFailsWithInvalidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minValidBits)
	if err != nil {
		t.Errorf("Failed to generate an invalid key, test broken: %+v", err)
	}
	key.D = big.NewInt(0) // Break the key
	if _, err := Sign("subject", "keyID", "audience", key); err != nil {
		t.Errorf("Did not fail to sign: %+v", err)
	}
}

func TestSignVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minValidBits)
	if err != nil {
		t.Errorf("Failed to generate a valid key, test broken: %+v", err)
	}
	token, _ := Sign("subject", "keyID", "audience", key)
	if Verify(token, &key.PublicKey) != nil {
		t.Errorf("Failed to verify token: %+v", err)
	}
}
