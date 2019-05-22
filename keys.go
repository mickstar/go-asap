package asap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincent-petithory/dataurl"
)

// KeyFetcher takes in an ASAP compliant kid and returns the public key
// associated with it for use in verifying tokens.
type KeyFetcher interface {
	Fetch(keyID string) (interface{}, error)
}

// NewPrivateKey attempts to decode the given bytes into a valid private key
// of some type and return something suitable for signing a token.
func NewPrivateKey(privateKeyData []byte) (interface{}, error) {
	var e error
	var privateKey interface{}
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

	privateKey, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	if e == nil {
		return privateKey, nil
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// NewMicrosPrivateKey plucks the key from the contracted ENV vars documented
// here: https://extranet.atlassian.com/pages/viewpage.action?pageId=2763562051
func NewMicrosPrivateKey() (interface{}, error) {
	return NewPrivateKey([]byte(os.Getenv("ASAP_PRIVATE_KEY")))
}

// NewPublicKey attempts to decode the given bytes into a valid public key of
// some type and return something suitable for verifying a token signature.
func NewPublicKey(publicKeyData []byte) (interface{}, error) {

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

func (f *httpFetcher) Fetch(keyID string) (interface{}, error) {
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
		var body, _ = ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("error fetching %s via HTTP. Code: %d Body: %s", pkURL.String(), resp.StatusCode, string(body))
	}

	var keyBytes []byte
	keyBytes, e = ioutil.ReadAll(resp.Body)
	if e != nil {
		return nil, e
	}

	return NewPublicKey(keyBytes)
}

type cacheFetcher struct {
	lock    sync.RWMutex
	wrapped KeyFetcher
	cache   map[string]interface{}
}

// NewCachingFetcher wraps a given KeyFetcher implementation with an in-memory
// cache for returned keys.
func NewCachingFetcher(wrapped KeyFetcher) KeyFetcher {
	return &cacheFetcher{sync.RWMutex{}, wrapped, make(map[string]interface{})}
}

func (f *cacheFetcher) Fetch(keyID string) (interface{}, error) {
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
func (f MultiKeyFetcher) Fetch(key string) (interface{}, error) {
	var pk interface{}
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

// KeyExpirationPair contains a public key along with that key's cache expiration time
type KeyExpirationPair struct {
	key        interface{}
	expiration time.Time
}

type expiringCacheFetcher struct {
	lock    sync.RWMutex
	baseURL string
	client  *http.Client
	cache   map[string]KeyExpirationPair
}

// NewExpiringCacheFetcher wraps a given KeyFetcher implementation that returns a KeyExpirationPair with an in-memory
// cache for returned keys.
func NewExpiringCacheFetcher(baseURL string, client *http.Client) KeyFetcher {
	return &expiringCacheFetcher{sync.RWMutex{}, baseURL, client, make(map[string]KeyExpirationPair)}
}

func getExpiryTime(header http.Header) time.Time {
	var cacheControl = header["Cache-Control"]
	r, _ := regexp.Compile("^max-age=([0-9]*)$")
	for _, v := range cacheControl {
		match := r.FindStringSubmatch(v)
		if len(match) != 2 {
			continue
		}
		seconds, e := strconv.ParseInt(match[1], 10, 64)
		if e != nil {
			continue
		}
		return time.Now().Add(time.Second * time.Duration(seconds))
	}
	expires, e := http.ParseTime(header.Get("Expires"))
	if e == nil {
		return expires
	}
	return time.Time{}
}

func (f *expiringCacheFetcher) fetchCached(keyID string) (*KeyExpirationPair, error) {
	var pkURL, e = url.Parse(f.baseURL)
	if e != nil {
		return nil, fmt.Errorf("cannot parse baseURL: %s", e)
	}
	pkURL.Path = path.Join(pkURL.Path, keyID)

	var resp *http.Response
	resp, e = f.client.Get(pkURL.String())
	if e != nil {
		return nil, fmt.Errorf("failed obtaining http response: %s", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body, _ = ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("error fetching %s via HTTP. Code: %d Body: %s", pkURL.String(), resp.StatusCode, string(body))
	}

	expiry := getExpiryTime(resp.Header)
	var keyBytes []byte
	keyBytes, e = ioutil.ReadAll(resp.Body)
	if e != nil {
		return nil, fmt.Errorf("failure reading response body: %s", e)
	}

	key, e := NewPublicKey(keyBytes)
	if e != nil {
		return nil, fmt.Errorf("failure parsing response body as public key: %s", e)
	}

	return &KeyExpirationPair{key, expiry}, nil
}

func (f *expiringCacheFetcher) Fetch(keyID string) (interface{}, error) {
	f.lock.RLock()
	var cached, ok = f.cache[keyID]
	f.lock.RUnlock()
	if ok && cached.expiration.After(time.Now()) {
		return cached.key, nil
	}
	var result, e = f.fetchCached(keyID)
	if e != nil {
		return nil, fmt.Errorf("failure obtaining a public key from wrapped fetcher: %s", e)
	}
	f.lock.Lock()
	defer f.lock.Unlock()
	f.cache[keyID] = *result
	return result.key, nil
}
