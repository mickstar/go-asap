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

func TestItReturnsKeyByID(t *testing.T) {
	s3mock, _ := newS3Mock()
	defer s3mock.Close()

	kp := &HTTPPublicKeyProvider{BaseURL: s3mock.URL}
	_, err := kp.GetPublicKey(keyID)
	if err != nil {
		t.Errorf("error in getting public key: %v", err)
	}
}

func TestItRespectsCacheControlHeaders(t *testing.T) {
	expectedRequestCount := 1
	testDuration := time.Duration(500) * time.Millisecond
	s3mock, requestCount := newS3Mock()
	defer s3mock.Close()

	kp := &HTTPPublicKeyProvider{BaseURL: s3mock.URL}

	startRequestLoop(testDuration, kp, t)

	if *requestCount != expectedRequestCount {
		t.Errorf("expected %d call to S3, but actual %d", expectedRequestCount, *requestCount)
	}
}
func TestItInvalidatesCacheIfStale(t *testing.T) {
	expectedRequestCount := 3
	testDuration := time.Duration(2) * time.Second
	s3mock, requestCount := newS3Mock()
	defer s3mock.Close()

	kp := &HTTPPublicKeyProvider{
		BaseURL:           s3mock.URL,
		CacheTTLInSeconds: 1,
	}

	startRequestLoop(testDuration, kp, t)

	if *requestCount != expectedRequestCount {
		t.Errorf("expected %d calls to S3, but actual %d", expectedRequestCount, *requestCount)
	}
}

// ------------------------------------------ HELPERS ------------------------------------------

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

func startRequestLoop(duration time.Duration, kp *HTTPPublicKeyProvider, t *testing.T) {
	start := time.Now()
	for {
		if time.Since(start) >= duration {
			return
		}
		_, err := kp.GetPublicKey(keyID)
		if err != nil {
			t.Errorf("error in getting public key: %v", err)
		}

		time.Sleep(time.Duration(100) * time.Millisecond)
	}
}
