package main

import (
	jwt "github.com/dgrijalva/jwt-go"
	"time"
	"github.com/satori/go.uuid"
	"encoding/pem"
	"log"
	"crypto/x509"
	"crypto/rsa"
)

type ASAPConfiguration struct {
	KeyIdentifier     string
	ServiceIdentifier string
	Audience          string
	Identifier        string
	Subject           string
}

var algorithm = "RS256"

func PrivateKeyFromBytes(privateKeyData []byte) (*rsa.PrivateKey, error) {
	var block *pem.Block

	if block, _ = pem.Decode(privateKeyData); block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("No valid PEM data found")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func Sign(subject string, keyId string, audience string, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = map[string]interface{}{
		"alg": algorithm,
		"iss": subject,
		"kid": keyId,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"jti": uuid.NewV4(),
	}
	return token.SignedString(privateKey)
}

func Verify(tokenString string, rsa.PublicKey) (bool, error) {
	return true, nil
}
