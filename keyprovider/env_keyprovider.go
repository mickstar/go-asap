package keyprovider

import (
	"crypto"
	"errors"
	"os"

	"github.com/vincent-petithory/dataurl"
)

type EnvironmentPrivateKeyProvider struct {
	PrivateKeyEnvName string
}

func (kp *EnvironmentPrivateKeyProvider) GetPrivateKey() (crypto.PrivateKey, error) {
	if kp.PrivateKeyEnvName == "" {
		return nil, errors.New("no environment variable")
	}

	privateKey := os.Getenv(kp.PrivateKeyEnvName)
	if privateKey == "" {
		return nil, errors.New("environment variable not set")
	}

	dataURL, err := dataurl.DecodeString(privateKey)
	if err == nil {
		return privateKeyFromBytes(dataURL.Data)
	}

	return privateKeyFromBytes([]byte(privateKey))
}
