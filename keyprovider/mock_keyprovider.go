package keyprovider

import (
	"crypto/rsa"
)

type MockKeyProvider struct {
	PrivateKey *rsa.PrivateKey
	PublicKeys map[string]*rsa.PublicKey
	Err        error
}

func (kp *MockKeyProvider) GetPublicKey(keyID string) (publicKey *rsa.PublicKey, err error) {
	return kp.PublicKeys[keyID], kp.Err
}

func (kp *MockKeyProvider) GetPrivateKey() (privateKey *rsa.PrivateKey, err error) {
	return kp.PrivateKey, kp.Err
}
