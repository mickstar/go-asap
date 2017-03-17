package keyprovider

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const keyID = "abc123"

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
		"TestCachesByDefault":         {ttl: 0, expected: 1, retries: 2},
		"TestCachesIfTTLProvided":     {ttl: 600, expected: 1, retries: 2},
		"TestInvalidatesCacheIfStale": {ttl: -1, expected: 2, retries: 2},
	}
	for name, bundle := range testCases {
		t.Run(name, func(t *testing.T) {
			s3mock, requestCount := newS3Mock()
			defer s3mock.Close()
			kp := &HTTPPublicKeyProvider{BaseURL: s3mock.URL, CacheTTLInSeconds: bundle.ttl}
			startRequestLoop(bundle.retries, kp, t)
			if *requestCount != bundle.expected {
				t.Fatalf("expected %d call(s) to S3, but actually performed %d", bundle.expected, *requestCount)
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
		io.WriteString(w, PublicKeyString)
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
