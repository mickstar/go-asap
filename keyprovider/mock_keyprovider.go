package keyprovider

import (
	"crypto"
	"errors"
)

type MockKeyProvider struct {
	PrivateKey crypto.PrivateKey
	PublicKeys map[string]crypto.PublicKey
	Err        error
}

func (kp *MockKeyProvider) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	key, ok := kp.PublicKeys[keyID]
	if !ok {
		return nil, errors.New("couldn't find key")
	}

	return key, kp.Err
}

func (kp *MockKeyProvider) GetPrivateKey() (crypto.PrivateKey, error) {
	return kp.PrivateKey, kp.Err
}
