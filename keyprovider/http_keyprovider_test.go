package keyprovider

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	publicKeyString = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIXNCB3YktXiCiXiN1yR
W+Ox9IqN2aenMKG9NHdOBlwp/2BQkm+G4nRjkdfn+6XnmrLeLS6dA/gTj03tJ3YN
JoqkjAcL2+x0SU3PtDYJO29TFOvIWlq2iJyTukYdlSXLhY5U3hyv/BdgI9gd6D2T
c6sy9i3CnkKSBlPniRQC2bor5ZzCLxr7NWMfe1HsAQExw6+iGwVtaNjP4wX2kMzA
w6cPNYKsZqpjXx8/GzkralkXZvBhW6IvVQe4EZjZW8MSoK7Gb6IAV+BM0ltOasY7
OOPQvTjL/3Aj0KJSAjrpbdFzYzwpIqUpwYFKW53y9eBnd2QlarrOnOGsdRBbCctV
2QIDAQAB
-----END PUBLIC KEY-----
`
	keyID = "abc123"
)

func TestCacheControl(t *testing.T) {
	testCases := map[string]*cacheControlTestBundle{
		"TestCacheControlDefaultsTo10Minutes": {kp: new(HTTPPublicKeyProvider), expected: defaultCacheControl},
		"TestCacheControlNoCacheForNegative":  {kp: &HTTPPublicKeyProvider{CacheTTLInSeconds: -1}, expected: noCacheControl},
		"TestCacheControlAppliesConfig":       {kp: &HTTPPublicKeyProvider{CacheTTLInSeconds: 1}, expected: "private, max-age=1"},
	}
	for name, bundle := range testCases {
		t.Run(name, func(t *testing.T) {
			cc := cacheControl(bundle.kp)
			if cc != bundle.expected {
				t.Errorf("wrong Cache-Control, expected %s, but actual %s", bundle.expected, cc)
			}
		})
	}
}

func TestItRespectsCacheControlHeaders(t *testing.T) {
	testCases := map[string]*kpTestBundle{
		"TestItCachesByDefault":         {ttl: 0, expected: 1, retries: 2},
		"TestItCachesIfTTLProvided":     {ttl: 600, expected: 1, retries: 2},
		"TestItInvalidatesCacheIfStale": {ttl: -1, expected: 2, retries: 2},
	}
	for name, bundle := range testCases {
		t.Run(name, func(t *testing.T) {
			s3mock, requestCount := newS3Mock()
			defer s3mock.Close()
			kp := &HTTPPublicKeyProvider{BaseURL: s3mock.URL, CacheTTLInSeconds: bundle.ttl}
			startRequestLoop(bundle.retries, kp, t)
			if *requestCount != bundle.expected {
				t.Errorf("expected %d call to S3, but actual %d", bundle.expected, *requestCount)
			}
		})
	}
}

// ------------------------------------------ HELPERS ------------------------------------------

type cacheControlTestBundle struct {
	kp       *HTTPPublicKeyProvider
	expected string
}

type kpTestBundle struct {
	ttl      int
	expected int
	retries  int
}

func newS3Mock() (*httptest.Server, *int) {
	requestCount := 0
	router := http.NewServeMux()
	router.HandleFunc("/"+keyID, func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Header().Add("Date", time.Now().Format(time.RFC1123))
		io.WriteString(w, publicKeyString)
	})
	return httptest.NewServer(router), &requestCount
}

func startRequestLoop(retriesCount int, kp *HTTPPublicKeyProvider, t *testing.T) {
	for i := 0; i < retriesCount; i++ {
		_, err := kp.GetPublicKey(keyID)
		if err != nil {
			t.Errorf("error in getting public key: %v", err)
		}
	}
}
