package asap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"bitbucket.org/atlassian/go-asap/v2/internal/keyrefresh"
	"github.com/vincent-petithory/dataurl"
)

// KeyFetcher takes in an ASAP compliant kid and returns the public key
// associated with it for use in verifying tokens.
type KeyFetcher interface {
	Fetch(keyID string) (any, error)
}

// NewPrivateKey attempts to decode the given bytes into a valid private key
// of some type and return something suitable for signing a token.
func NewPrivateKey(privateKeyData []byte) (any, error) {
	var e error
	var privateKey any
	var dataURL *dataurl.DataURL
	// PEM files are typically multi-line, which makes the raw form difficult to be stored in evnironment variables.
	// We first attempt to decode the data. If we fail, then proceed with the original input.
	if dataURL, e = dataurl.DecodeString(string(privateKeyData)); e == nil {
		privateKeyData = dataURL.Data
	}

	privateKey, e = x509.ParsePKCS8PrivateKey(privateKeyData)
	if e == nil {
		return privateKey, nil
	}

	var block, _ = pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("No valid PEM data found")
	}

	privateKey, e = x509.ParsePKCS8PrivateKey(block.Bytes)
	if e == nil {
		return privateKey, nil
	}

	privateKey, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	if e == nil {
		return privateKey, nil
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// NewMicrosPrivateKey plucks the key from the contracted ENV vars documented
// here: https://extranet.atlassian.com/pages/viewpage.action?pageId=2763562051
func NewMicrosPrivateKey() (any, error) {
	return NewPrivateKey([]byte(os.Getenv("ASAP_PRIVATE_KEY")))
}

// NewPublicKey attempts to decode the given bytes into a valid public key of
// some type and return something suitable for verifying a token signature.
func NewPublicKey(publicKeyData []byte) (any, error) {

	var block, _ = pem.Decode(publicKeyData)
	if block == nil {
		return nil, errors.New("No valid PEM data found")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}

type httpFetcher struct {
	baseURL string
	client  *http.Client
}

// NewHTTPKeyFetcher pulls public keys from an HTTP accessible source.
func NewHTTPKeyFetcher(baseURL string, client *http.Client) KeyFetcher {
	return &httpFetcher{baseURL, client}
}

// NewMultiFetcher will return the first non error fetch result
func NewMultiFetcher(fetchers ...KeyFetcher) KeyFetcher {
	return MultiKeyFetcher(fetchers)
}

// NewMicrosKeyFetcher pulls public keys from the shared s3 bucket given as
// part of the ASAP env var contract in Micros. Documentation for contract:
// https://extranet.atlassian.com/pages/viewpage.action?pageId=2763562051
func NewMicrosKeyFetcher(client *http.Client) KeyFetcher {
	return NewMultiFetcher(
		&httpFetcher{
			baseURL: os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"),
			client:  client,
		},
		&httpFetcher{
			baseURL: os.Getenv("ASAP_PUBLIC_KEY_FALLBACK_REPOSITORY_URL"),
			client:  client,
		},
	)
}

func (f *httpFetcher) Fetch(keyID string) (any, error) {
	var pkURL, e = url.Parse(f.baseURL)
	if e != nil {
		return nil, e
	}
	pkURL.Path = path.Join(pkURL.Path, keyID)

	var resp *http.Response
	resp, e = f.client.Get(pkURL.String())
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body, _ = io.ReadAll(resp.Body)
		return nil, fmt.Errorf("error fetching %s via HTTP. Code: %d Body: %s", pkURL.String(), resp.StatusCode, string(body))
	}

	var keyBytes []byte
	keyBytes, e = io.ReadAll(resp.Body)
	if e != nil {
		return nil, e
	}

	return NewPublicKey(keyBytes)
}

type cacheFetcher struct {
	lock    sync.RWMutex
	wrapped KeyFetcher
	cache   map[string]any
}

// NewCachingFetcher wraps a given KeyFetcher implementation with an in-memory
// cache for returned keys.
func NewCachingFetcher(wrapped KeyFetcher) KeyFetcher {
	return &cacheFetcher{sync.RWMutex{}, wrapped, make(map[string]any)}
}

func (f *cacheFetcher) Fetch(keyID string) (any, error) {
	f.lock.RLock()
	var cached, ok = f.cache[keyID]
	f.lock.RUnlock()
	if ok {
		return cached, nil
	}
	var result, e = f.wrapped.Fetch(keyID)
	if e == nil {
		f.lock.Lock()
		defer f.lock.Unlock()
		f.cache[keyID] = result
	}
	return result, e
}

// MultiKeyFetcher returns the first non error result from its list of fetchers
type MultiKeyFetcher []KeyFetcher

// Fetch iterates through the list of fetchers returning first fetch result that
// succeeds
func (f MultiKeyFetcher) Fetch(key string) (any, error) {
	var pk any
	var errs []string
	var err error
	for _, fetcher := range f {
		pk, err = fetcher.Fetch(key)
		if err == nil {
			return pk, nil
		}
		errs = append(errs, err.Error())
	}
	return nil, errors.New(strings.Join(errs, ", "))
}

// NewExpiringCacheFetcher returns the bounded, expiring public-key fetcher.
func NewExpiringCacheFetcher(baseURL string, client *http.Client, _ time.Duration) (KeyFetcher, error) {
	return newQueuedRefreshFetcher(baseURL, client, nil)
}

// NewExpiringCacheFetcherWithStats returns the bounded, expiring public-key
// fetcher and reports its cache activity through stats.
func NewExpiringCacheFetcherWithStats(baseURL string, client *http.Client, stats func(stat string, count float64, tags ...string)) (KeyFetcher, error) {
	return newQueuedRefreshFetcher(baseURL, client, stats)
}

func newQueuedRefreshFetcher(baseURL string, client *http.Client, stats func(stat string, count float64, tags ...string)) (KeyFetcher, error) {
	fetcher, err := keyrefresh.NewFetcher(keyrefresh.Config{
		BaseURL:        baseURL,
		HTTPClient:     client,
		ParsePublicKey: NewPublicKey,
		Stats:          stats,
	})
	if err != nil {
		return nil, err
	}
	return fetcher, nil
}
