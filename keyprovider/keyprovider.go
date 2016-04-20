package keyprovider

import (
	"crypto/rsa"
)

type KeyProvider interface {
	GetPrivateKey() (*rsa.PrivateKey, error)
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
}
