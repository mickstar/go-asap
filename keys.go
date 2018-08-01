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
	"sync"

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
	var d, e = dataurl.DecodeString(os.Getenv("ASAP_PRIVATE_KEY"))
	if e != nil {
		return nil, e
	}
	return NewPrivateKey(d.Data)
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

// NewMicrosKeyFetcher pulls public keys from the shared s3 bucket given as
// part of the ASAP env var contract in Micros. Documentation for contract:
// https://extranet.atlassian.com/pages/viewpage.action?pageId=2763562051
func NewMicrosKeyFetcher(client *http.Client) KeyFetcher {
	return &httpFetcher{os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"), client}
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
		return nil, fmt.Errorf("Error fetching %s via HTTP. Code: %d Body: %s", pkURL.String(), resp.StatusCode, string(body))
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
