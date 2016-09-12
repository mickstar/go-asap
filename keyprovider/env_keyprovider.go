package keyprovider

import (
	"errors"
	"os"
	"github.com/vincent-petithory/dataurl"
)

type EnvironmentPrivateKeyProvider struct {
	PrivateKeyEnvName string
}

func (kp *EnvironmentPrivateKeyProvider) GetPrivateKey() (interface{}, error) {
	if kp.PrivateKeyEnvName == "" {
		return nil, errors.New("no environment variable")
	}

	privateKey := os.Getenv(kp.PrivateKeyEnvName)
	if privateKey == "" {
		return nil, errors.New("environment variable not set")
	}

	dataURL, err := dataurl.DecodeString(privateKey)
	if err == nil {
		return PrivateKeyFromBytes(dataURL.Data)
	}

	return PrivateKeyFromBytes([]byte(privateKey))
}
