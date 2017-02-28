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

const defaultCacheTTLInSeconds = 600

var defaultClient = &http.Client{
	Timeout:   time.Second * 2,
	Transport: httpcache.NewMemoryCacheTransport(), // Respect HTTP cache control headers
}

type HTTPPublicKeyProvider struct {
	BaseURL           string
	Client            *http.Client
	CacheTTLInSeconds int
}

func (kp *HTTPPublicKeyProvider) GetPublicKey(keyID string) (interface{}, error) {
	pkURL, err := url.Parse(kp.BaseURL)
	if err != nil {
		return nil, err
	}
	pkURL.Path = path.Join(pkURL.Path, keyID)

	netClient := kp.Client
	if netClient == nil {
		netClient = defaultClient
	}

	cacheTTL := kp.CacheTTLInSeconds
	if cacheTTL == 0 {
		cacheTTL = defaultCacheTTLInSeconds
	}

	req, err := http.NewRequest(http.MethodGet, pkURL.String(), nil)
	req.Header.Add("Cache-Control", fmt.Sprintf("private, max-age=%d", cacheTTL))
	if err != nil {
		return nil, err
	}

	resp, err := netClient.Do(req)
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
