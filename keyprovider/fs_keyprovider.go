package keyprovider

import (
	"crypto"
	"io/ioutil"
	"path/filepath"
)

type FSKeyProvider struct {
	PrivateKeyPath    string
	PublicKeyDir      string
	PublicKeyFilename string
}

func (kp *FSKeyProvider) GetPrivateKey() (crypto.PrivateKey, error) {
	privateKey, err := ioutil.ReadFile(kp.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	return privateKeyFromBytes(privateKey)
}

func (kp *FSKeyProvider) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	path := filepath.Join(kp.PublicKeyDir, keyID)

	// Best case scenario, the keyID contains the file.
	publicKey, err := ioutil.ReadFile(path)

	// The public key filename is provided
	if err != nil && kp.PublicKeyFilename != "" {
		publicKey, err = ioutil.ReadFile(filepath.Join(path, kp.PublicKeyFilename))
	}

	// Can't get the public key
	if err != nil {
		return nil, err
	}

	return publicKeyFromBytes(publicKey)
}
