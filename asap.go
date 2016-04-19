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

func PublicKeyFromBytes(publicKeyData []byte) (publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode(publicKeyData)

	publicKeyUnsafe, err := x509.ParsePKIXPublicKey(block.Bytes)
	if publicKeyUnsafe == nil && err == nil {
		return nil, errors.New("Unsupported algorithm")
	}
	return publicKeyUnsafe.(*rsa.PublicKey), nil
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

func Verify(token []byte, publicKey *rsa.PublicKey) (err error) {
	jwt, err := jws.ParseJWT(token)
	if err != nil {
		return err
	}
	return jwt.Validate(publicKey, signingMethod)
}
