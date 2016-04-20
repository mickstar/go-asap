package keystores

import (
	"crypto/rsa"
)

type MockKeyStore struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
	Err        error
}

func (ks *MockKeyStore) GetPrivateKey() (privateKey *rsa.PrivateKey, err error) {
	return ks.PrivateKey, ks.Err
}

func (ks *MockKeyStore) GetPublicKey(keyID string) (publicKey *rsa.PublicKey, err error) {
	return ks.PublicKeys[keyID], ks.Err
}
