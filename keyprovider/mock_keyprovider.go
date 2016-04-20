package keyprovider

import (
	"crypto/rsa"
)

type MockKeyProvider struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
	Err        error
}

func (ks *MockKeyProvider) GetPrivateKey() (privateKey *rsa.PrivateKey, err error) {
	return ks.PrivateKey, ks.Err
}

func (ks *MockKeyProvider) GetPublicKey(keyID string) (publicKey *rsa.PublicKey, err error) {
	return ks.PublicKeys[keyID], ks.Err
}
