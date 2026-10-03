package keyrefresh

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/cachecontrol/cacheobject"
)

type keyStoreClient struct {
	baseURL        string
	httpClient     *http.Client
	parsePublicKey func([]byte) (any, error)
	timeNow        func() time.Time
}

func newKeyStoreClient(baseURL string, httpClient *http.Client, parsePublicKey func([]byte) (any, error)) (*keyStoreClient, error) {
	var _, e = url.Parse(baseURL)
	if e != nil {
		return nil, fmt.Errorf("cannot parse baseURL: %s", e)
	}

	if !strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL + "/"
	}

	return &keyStoreClient{
		baseURL:        baseURL,
		httpClient:     httpClient,
		parsePublicKey: parsePublicKey,
		timeNow:        time.Now,
	}, nil
}

func (c *keyStoreClient) fetch(keyID string) (keyExpirationPair, error) {
	httpURL := c.baseURL + keyID
	resp, err := c.httpClient.Get(httpURL)
	if err != nil {
		return keyExpirationPair{}, lookupError{fmt.Errorf("failed obtaining http response: %s", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body, _ = io.ReadAll(resp.Body)
		err := fmt.Errorf("error fetching %s via HTTP. Code: %d Body: %s", httpURL, resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
			return keyExpirationPair{}, lookupMissError{err}
		}
		return keyExpirationPair{}, lookupError{err}
	}

	expiry, staleOk := getExpiryAndStaleOk(resp.Header, c.timeNow)
	var keyBytes []byte
	keyBytes, err = io.ReadAll(resp.Body)
	if err != nil {
		return keyExpirationPair{}, badResponseError{fmt.Errorf("failure reading response body: %s", err)}
	}

	key, e := c.parsePublicKey(keyBytes)
	if e != nil {
		return keyExpirationPair{}, badResponseError{fmt.Errorf("failure parsing response body as public key: %s", e)}
	}

	return keyExpirationPair{key, expiry, staleOk}, nil
}

func getExpiryAndStaleOk(header http.Header, timeNow func() time.Time) (time.Time, time.Duration) {
	cacheControl, ok := header["Cache-Control"]
	if !ok {
		return getExpiresTime(header, timeNow)
	}
	responseDirs, err := cacheobject.ParseResponseCacheControl(strings.Join(cacheControl, ","))
	if err != nil {
		return getExpiresTime(header, timeNow)
	}

	if responseDirs.MaxAge != -1 {
		if responseDirs.StaleWhileRevalidate != -1 {
			return timeNow().Add(time.Duration(responseDirs.MaxAge) * time.Second),
				time.Duration(responseDirs.StaleWhileRevalidate) * time.Second
		}
		return timeNow().Add(time.Duration(responseDirs.MaxAge) * time.Second), time.Duration(0)
	}

	return getExpiresTime(header, timeNow)
}

func getExpiresTime(header http.Header, timeNow func() time.Time) (time.Time, time.Duration) {
	expires, e := http.ParseTime(header.Get("Expires"))
	if e != nil {
		return timeNow().Add(time.Minute * 10), time.Duration(time.Minute * 20)
	}

	return expires, time.Duration(0)
}
