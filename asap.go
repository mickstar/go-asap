package asap

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/satori/go.uuid"
	"time"
)

type ASAPConfiguration struct {
	KeyIdentifier     string
	ServiceIdentifier string
	Audience          string
	Identifier        string
	Subject           string
}

var signingMethod = crypto.SigningMethodRS256

func nullPtrError(varName string) error {
	return errors.New("Null pointer: " + varName)
}

func PrivateKeyFromBytes(privateKeyData []byte) (privateKey *rsa.PrivateKey, err error) {
	var block *pem.Block

	if block, _ = pem.Decode(privateKeyData); block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("No valid PEM data found")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func Sign(subject string, keyID string, audience string, privateKey *rsa.PrivateKey) (token []byte, err error) {
	if privateKey == nil {
		return nil, nullPtrError("Sign::privateKey")
	}
	now := time.Now()
	jit := uuid.NewV4().String()
	exp := now.Add(time.Minute).Unix()

	claims := jws.Claims{}
	claims.SetSubject(subject)
	claims.SetJWTID(jit)
	claims.SetIssuedAt(float64(now.Unix()))
	claims.SetExpiration(float64(exp))
	claims.SetAudience(audience)

	jwt := jws.NewJWT(claims, signingMethod)
	return jwt.Serialize(privateKey)
}

func Verify(token []byte, publicKey *rsa.PublicKey) (verified bool, err error) {
	jwt, err := jws.ParseJWT(token)
	if err != nil {
		return false, err
	}

	validationErr := jwt.Validate(publicKey, signingMethod)
	return validationErr == nil, validationErr
}
