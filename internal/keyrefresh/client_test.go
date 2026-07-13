package keyrefresh

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripResponse struct {
	statusCode int
	header     http.Header
	body       string
	err        error
	bodyErr    error
	started    chan<- struct{}
	block      <-chan struct{}
}

type recordingTransport struct {
	lock      sync.Mutex
	requests  []*http.Request
	responses []roundTripResponse
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.lock.Lock()
	t.requests = append(t.requests, req)
	response := t.responses[len(t.responses)-1]
	if len(t.requests) <= len(t.responses) {
		response = t.responses[len(t.requests)-1]
	}
	t.lock.Unlock()

	if response.started != nil {
		select {
		case response.started <- struct{}{}:
		default:
		}
	}
	if response.block != nil {
		<-response.block
	}
	if response.err != nil {
		return nil, response.err
	}
	statusCode := response.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	body := ioutil.NopCloser(bytes.NewBufferString(response.body))
	if response.bodyErr != nil {
		body = errReadCloser{err: response.bodyErr}
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     response.header,
		Body:       body,
	}, nil
}

func (t *recordingTransport) requestCount() int {
	t.lock.Lock()
	defer t.lock.Unlock()
	return len(t.requests)
}

func (t *recordingTransport) lastURL() string {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.requests[len(t.requests)-1].URL.String()
}

type errReadCloser struct {
	err error
}

func (r errReadCloser) Read(_ []byte) (int, error) {
	return 0, r.err
}

func (r errReadCloser) Close() error {
	return nil
}

func parseString(data []byte) (interface{}, error) {
	return string(data), nil
}

func parseFailure(_ []byte) (interface{}, error) {
	return nil, errors.New("parse failed")
}

func TestNewKeyStoreClientValidatesAndNormalizesBaseURL(t *testing.T) {
	client, err := newKeyStoreClient("http://keys.example/base", http.DefaultClient, parseString)
	require.NoError(t, err)
	require.Equal(t, "http://keys.example/base/", client.baseURL)

	_, err = newKeyStoreClient("%", http.DefaultClient, parseString)
	require.Error(t, err)
}

func TestKeyStoreClientFetchSuccess(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &recordingTransport{
		responses: []roundTripResponse{{
			header: http.Header{"Cache-Control": {"max-age=60, stale-while-revalidate=30"}},
			body:   "public-key",
		}},
	}
	client, err := newKeyStoreClient("http://keys.example/base", &http.Client{Transport: transport}, parseString)
	require.NoError(t, err)
	client.timeNow = func() time.Time { return now }

	pair, err := client.fetch("kid")

	require.NoError(t, err)
	require.Equal(t, "public-key", pair.key)
	require.Equal(t, now.Add(time.Minute), pair.expiration)
	require.Equal(t, 30*time.Second, pair.staleWhileRevalidate)
	require.Equal(t, "http://keys.example/base/kid", transport.lastURL())
}

func TestKeyStoreClientFetchErrors(t *testing.T) {
	tests := []struct {
		name      string
		response  roundTripResponse
		parse     func([]byte) (interface{}, error)
		assertErr func(*testing.T, error)
	}{
		{
			name:     "transport error",
			response: roundTripResponse{err: errors.New("network failed")},
			parse:    parseString,
			assertErr: func(t *testing.T, err error) {
				_, ok := err.(lookupError)
				require.True(t, ok)
			},
		},
		{
			name:     "not found is a temporary lookup miss",
			response: roundTripResponse{statusCode: http.StatusNotFound, body: "missing"},
			parse:    parseString,
			assertErr: func(t *testing.T, err error) {
				_, ok := err.(lookupMissError)
				require.True(t, ok)
			},
		},
		{
			name:     "server error",
			response: roundTripResponse{statusCode: http.StatusInternalServerError, body: "failed"},
			parse:    parseString,
			assertErr: func(t *testing.T, err error) {
				_, ok := err.(lookupError)
				require.True(t, ok)
			},
		},
		{
			name:     "body read error",
			response: roundTripResponse{bodyErr: errors.New("read failed")},
			parse:    parseString,
			assertErr: func(t *testing.T, err error) {
				_, ok := err.(badResponseError)
				require.True(t, ok)
			},
		},
		{
			name:     "parse error",
			response: roundTripResponse{body: "not a key"},
			parse:    parseFailure,
			assertErr: func(t *testing.T, err error) {
				_, ok := err.(badResponseError)
				require.True(t, ok)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &recordingTransport{responses: []roundTripResponse{test.response}}
			client, err := newKeyStoreClient("http://keys.example", &http.Client{Transport: transport}, test.parse)
			require.NoError(t, err)

			_, err = client.fetch("kid")

			require.Error(t, err)
			test.assertErr(t, err)
		})
	}
}

func TestExpiryParsing(t *testing.T) {
	now := time.Unix(1000, 0)
	timeNow := func() time.Time { return now }
	expires := now.Add(2 * time.Minute).UTC().Format(http.TimeFormat)

	expiry, stale := getExpiryAndStaleOk(http.Header{"Cache-Control": {"max-age=5"}}, timeNow)
	require.Equal(t, now.Add(5*time.Second), expiry)
	require.Equal(t, time.Duration(0), stale)

	expiry, stale = getExpiryAndStaleOk(http.Header{"Cache-Control": {"not-valid"}, "Expires": {expires}}, timeNow)
	require.Equal(t, now.Add(2*time.Minute).UTC(), expiry)
	require.Equal(t, time.Duration(0), stale)

	expiry, stale = getExpiryAndStaleOk(http.Header{"Cache-Control": {"no-store"}, "Expires": {expires}}, timeNow)
	require.Equal(t, now.Add(2*time.Minute).UTC(), expiry)
	require.Equal(t, time.Duration(0), stale)

	expiry, stale = getExpiryAndStaleOk(http.Header{}, timeNow)
	require.Equal(t, now.Add(10*time.Minute), expiry)
	require.Equal(t, 20*time.Minute, stale)
}
