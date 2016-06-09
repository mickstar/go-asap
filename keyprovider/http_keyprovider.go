package keyprovider

import (
	"io/ioutil"
	"net/http"
	"path"
)

type HTTPPublicKeyProvider struct {
	BaseURL string
}

func (kp *HTTPPublicKeyProvider) GetPublicKey(keyID string) (interface{}, error) {
	resp, err := http.Get(path.Join(kp.BaseURL, keyID))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, err
	}

	publicKey, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(publicKey)
}
