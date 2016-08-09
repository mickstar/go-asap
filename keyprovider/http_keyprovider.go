package keyprovider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

type HTTPPublicKeyProvider struct {
	BaseURL string
}

func (kp *HTTPPublicKeyProvider) GetPublicKey(keyID string) (interface{}, error) {
	pkURL, err := url.Parse(kp.BaseURL)
	if err != nil {
		return nil, err
	}
	pkURL.Path = path.Join(pkURL.Path, keyID)

	resp, err := http.Get(pkURL.String())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET '%s' returned status code %d", pkURL.String(), resp.StatusCode)
	}

	publicKey, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(publicKey)
}
