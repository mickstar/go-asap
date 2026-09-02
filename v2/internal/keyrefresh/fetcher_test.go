package keyrefresh

import (
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewFetcherValidatesConfigAndSetsQueueSize(t *testing.T) {
	_, err := NewFetcher(Config{BaseURL: "http://keys.example", HTTPClient: http.DefaultClient})
	require.Error(t, err)

	_, err = NewFetcher(Config{
		BaseURL:        "%",
		HTTPClient:     http.DefaultClient,
		ParsePublicKey: parseString,
	})
	require.Error(t, err)

	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: &recordingTransport{responses: []roundTripResponse{{body: "key"}}}},
		ParsePublicKey: parseString,
	})
	require.NoError(t, err)
	require.Equal(t, defaultQueueSize, cap(fetcher.queue))
	require.NoError(t, fetcher.Close())

	fetcher, err = NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: &recordingTransport{responses: []roundTripResponse{{body: "key"}}}},
		ParsePublicKey: parseString,
		QueueSize:      2,
	})
	require.NoError(t, err)
	require.Equal(t, 2, cap(fetcher.queue))
	require.NoError(t, fetcher.Close())
}

func TestFetcherFetchMissAndFreshHit(t *testing.T) {
	stats := &statRecorder{}
	transport := &recordingTransport{
		responses: []roundTripResponse{{
			header: http.Header{"Cache-Control": {"max-age=60"}},
			body:   "remote",
		}},
	}
	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: transport},
		ParsePublicKey: parseString,
		Stats:          stats.record,
	})
	require.NoError(t, err)
	defer fetcher.Close()

	value, err := fetcher.Fetch("kid")
	require.NoError(t, err)
	require.Equal(t, "remote", value)

	value, err = fetcher.Fetch("kid")
	require.NoError(t, err)
	require.Equal(t, "remote", value)
	require.Equal(t, 1, transport.requestCount())
	require.Equal(t, float64(1), stats.get(statCacheMiss))
	require.Equal(t, float64(1), stats.get(statCacheForceReload))
	require.Equal(t, float64(1), stats.get(statCachedKey))
}

func TestFetcherStaleRefreshSuppressesDuplicateQueuedWork(t *testing.T) {
	transport := &recordingTransport{
		responses: []roundTripResponse{
			{
				header: http.Header{"Cache-Control": {"max-age=0, stale-while-revalidate=60"}},
				body:   "initial",
			},
			{
				header: http.Header{"Cache-Control": {"max-age=60, stale-while-revalidate=60"}},
				body:   "refreshed",
			},
		},
	}
	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: transport},
		ParsePublicKey: parseString,
	})
	require.NoError(t, err)
	defer fetcher.Close()

	value, err := fetcher.Fetch("kid")
	require.NoError(t, err)
	require.Equal(t, "initial", value)

	for range 500 {
		_, err := fetcher.Fetch("kid")
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		value, err := fetcher.Fetch("kid")
		return err == nil &&
			reflect.DeepEqual(value, "refreshed") &&
			transport.requestCount() == 2
	}, time.Second, time.Millisecond)
}

func TestFetcherNegativeCacheHit(t *testing.T) {
	stats := &statRecorder{}
	transport := &recordingTransport{
		responses: []roundTripResponse{{statusCode: http.StatusNotFound, body: "missing"}},
	}
	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: transport},
		ParsePublicKey: parseString,
		Stats:          stats.record,
	})
	require.NoError(t, err)
	defer fetcher.Close()

	value, err := fetcher.Fetch("kid")
	require.Nil(t, value)
	_, ok := err.(lookupMissError)
	require.True(t, ok)

	value, err = fetcher.Fetch("kid")
	require.Nil(t, value)
	_, ok = err.(lookupMissError)
	require.True(t, ok)
	require.Equal(t, 1, transport.requestCount())
	require.Equal(t, float64(1), stats.get(statCacheMiss))
	require.Equal(t, float64(1), stats.get(statCachedLookupMiss))
}

func TestFetcherQueueDropAndClose(t *testing.T) {
	fetcher := &Fetcher{queue: make(chan string, 1)}
	fetcher.enqueueRefresh("first")
	fetcher.enqueueRefresh("second")
	require.Equal(t, 1, len(fetcher.queue))

	stop := make(chan struct{})
	fetcher = &Fetcher{
		queue: make(chan string),
		stop:  make(chan struct{}),
	}
	go func() {
		fetcher.run()
		close(stop)
	}()
	close(fetcher.stop)
	<-stop

	realFetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: &recordingTransport{responses: []roundTripResponse{{body: "key"}}}},
		ParsePublicKey: parseString,
	})
	require.NoError(t, err)
	require.NoError(t, realFetcher.Close())
	require.NoError(t, realFetcher.Close())
}

func BenchmarkFetcherFreshHit(b *testing.B) {
	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: benchmarkTransport{}},
		ParsePublicKey: parseString,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer fetcher.Close()

	if _, err := fetcher.Fetch("kid"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := fetcher.Fetch("kid"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFetcherHighCardinalityMiss(b *testing.B) {
	fetcher, err := NewFetcher(Config{
		BaseURL:        "http://keys.example",
		HTTPClient:     &http.Client{Transport: benchmarkTransport{}},
		ParsePublicKey: parseString,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer fetcher.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, err := fetcher.Fetch(strconv.Itoa(i)); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkTransport struct{}

func (benchmarkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Cache-Control": {"max-age=60"}},
		Body:       io.NopCloser(strings.NewReader("key")),
	}, nil
}
