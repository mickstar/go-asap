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
	defaultClient = &http.Client{
		Timeout:   time.Second * 2,
		Transport: httpcache.NewMemoryCacheTransport(), // Respect HTTP cache control headers
	}
)

type HTTPPublicKeyProvider struct {
	BaseURL string
	client  *http.Client
}

func (kp *HTTPPublicKeyProvider) GetPublicKey(keyID string) (interface{}, error) {
	pkURL, err := url.Parse(kp.BaseURL)
	if err != nil {
		return nil, err
	}
	pkURL.Path = path.Join(pkURL.Path, keyID)

	netClient := kp.client
	if netClient == nil {
		netClient = defaultClient
	}

	resp, err := netClient.Do(&http.Request{
		Method: http.MethodGet,
		URL:    pkURL,
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
