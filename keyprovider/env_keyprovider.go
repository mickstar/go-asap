package keyprovider

import (
	"errors"
	"os"
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

	return PrivateKeyFromBytes([]byte(privateKey))
}
