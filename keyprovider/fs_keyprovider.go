package keyprovider

import (
	"crypto/rsa"
	"io/ioutil"
	"path/filepath"
)

type FSKeyProvider struct {
	PrivateKeyPath    string
	PublicKeyDir      string
	PublicKeyFilename string
}

func (kp *FSKeyProvider) GetPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := ioutil.ReadFile(kp.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return PrivateKeyFromBytes(privateKey)
}

func (kp *FSKeyProvider) GetPublicKey(keyID string) (*rsa.PublicKey, error) {

	var publicKey []byte
	var err error

	path := filepath.Join(kp.PublicKeyDir, keyID)

	// Best case scenario, the keyID contains the file.
	if publicKey, err = ioutil.ReadFile(path); err == nil {
		return PublicKeyFromBytes(publicKey)
	}

	// The public key filename is provided
	if publicKey, err = ioutil.ReadFile(filepath.Join(path, kp.PublicKeyFilename)); err == nil {
		return PublicKeyFromBytes(publicKey)
	}

	// Can't get the public key
	return nil, err
}
