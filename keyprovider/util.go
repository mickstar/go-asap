package keyprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

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
