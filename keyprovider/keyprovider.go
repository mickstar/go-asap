package keyprovider

import (
	"crypto/rsa"
)

type PublicKeyProvider interface {
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
}
