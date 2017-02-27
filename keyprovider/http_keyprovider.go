package keyprovider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/gregjones/httpcache"
)

var (
	client = &http.Client{
		Timeout: time.Second * 1,
		Transport: httpcache.NewMemoryCacheTransport(), // Respect HTTP cache control headers
	}
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

	resp, err := client.Do(&http.Request{
		Method: http.MethodGet,
		URL: pkURL,
	})
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
