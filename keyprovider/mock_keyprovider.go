package keyprovider

type MockKeyProvider struct {
	PrivateKey interface{}
	PublicKeys map[string]interface{}
	Err        error
}

func (kp MockKeyProvider) GetPublicKey(keyID string) (interface{}, error) {
	return kp.PublicKeys[keyID], kp.Err
}

func (kp MockKeyProvider) GetPrivateKey() (interface{}, error) {
	return kp.PrivateKey, kp.Err
}
