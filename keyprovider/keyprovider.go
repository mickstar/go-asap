package keyprovider

import "crypto"

type PublicKeyProvider interface {
	GetPublicKey(keyID string) (crypto.PublicKey, error)
}

type PrivateKeyProvider interface {
	GetPrivateKey() (crypto.PrivateKey, error)
}
