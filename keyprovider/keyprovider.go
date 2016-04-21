package keyprovider

import (
	"crypto/rsa"
)

type PublicKeyProvider interface {
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
}

type PrivateKeyProvider interface {
	GetPrivateKey() (*rsa.PrivateKey, error)
}
