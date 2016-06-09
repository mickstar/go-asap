package keyprovider

type PublicKeyProvider interface {
	GetPublicKey(keyID string) (interface{}, error)
}

type PrivateKeyProvider interface {
	GetPrivateKey() (interface{}, error)
}
