package asap

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

const minValidBits = 2048

func TestParseToken(t *testing.T) {
	var e error
	var token Token

	var privateKey, _ = rsa.GenerateKey(rand.Reader, minValidBits)
	var claims = Claims{}
	claims.Set("TEST", "TEST")
	token = newJWT(claims, SigningMethodRS256)
	var data []byte
	data, e = token.Serialize(privateKey)
	if e != nil {
		t.Fatalf("Failed to sign token: %s", e)
	}
	token, e = ParseToken(string(data))
	if e != nil {
		t.Fatalf("Failed to parse token: %s", e)
	}
	if token.Claims().Get("TEST").(string) != "TEST" {
		t.Fatal("Did not find the test claims in the parsed token.")
	}
}
