package keyprovider

import (
	"crypto/rsa"
)

type MockKeyProvider struct {
	PublicKeys map[string]*rsa.PublicKey
	Err        error
}

func (ks *MockKeyProvider) GetPublicKey(keyID string) (publicKey *rsa.PublicKey, err error) {
	return ks.PublicKeys[keyID], ks.Err
}
