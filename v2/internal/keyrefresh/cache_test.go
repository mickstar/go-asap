package keyrefresh

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type statRecorder struct {
	lock  sync.Mutex
	calls map[string]float64
}

func (s *statRecorder) record(stat string, count float64, tags ...string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.calls == nil {
		s.calls = map[string]float64{}
	}
	s.calls[stat] += count
}

func (s *statRecorder) get(stat string) float64 {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.calls[stat]
}

func newTestKeyCache(t *testing.T, now time.Time, transport *recordingTransport, stats Stats) *keyCache {
	t.Helper()
	keyStore, err := newKeyStoreClient("http://keys.example", &http.Client{Transport: transport}, parseString)
	require.NoError(t, err)
	keyStore.timeNow = func() time.Time { return now }
	cache, err := newKeyCache(keyStore, stats)
	require.NoError(t, err)
	cache.timeNow = func() time.Time { return now }
	t.Cleanup(cache.close)
	return cache
}

func TestKeyCacheEntryConstructors(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := newKeyCacheEntry(keyExpirationPair{
		key:                  "key",
		expiration:           now,
		staleWhileRevalidate: time.Minute,
	})
	require.Equal(t, cacheEntryKey, entry.kind)
	require.Equal(t, "key", entry.key)
	require.Equal(t, now, entry.freshUntil)
	require.Equal(t, now.Add(time.Minute), entry.staleUntil)

	miss := lookupMissError{error: errors.New("missing")}
	missEntry := newKeyLookupMissCacheEntry(miss, now.Add(time.Second))
	require.Equal(t, cacheEntryLookupMiss, missEntry.kind)
	require.Equal(t, miss, missEntry.lookupMiss)
	require.Equal(t, now.Add(time.Second), missEntry.freshUntil)
	require.Equal(t, now.Add(time.Second), missEntry.staleUntil)
}

func TestKeyCacheStoreEntrySkipsExpiredEntry(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newTestKeyCache(t, now, &recordingTransport{responses: []roundTripResponse{{body: "remote"}}}, nil)
	cache.storeKey("expired", keyExpirationPair{key: "expired", expiration: now.Add(-time.Second)})
	cache.cache.Wait()

	_, ok := cache.cache.Get("expired")
	require.False(t, ok)
}

func TestKeyCacheBoundsHighCardinalityEntries(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := newTestKeyCache(t, now, &recordingTransport{}, nil)

	for i := range defaultMaxKeyCacheSize {
		cache.storeKey(strconv.Itoa(i), keyExpirationPair{key: "key", expiration: now.Add(time.Hour)})
	}
	cache.cache.Wait()

	for i := range defaultMaxKeyCacheSize {
		_, ok := cache.cache.Get(strconv.Itoa(i))
		require.True(t, ok)
	}

	for i := defaultMaxKeyCacheSize; i < defaultMaxKeyCacheSize*2; i++ {
		cache.storeKey(strconv.Itoa(i), keyExpirationPair{
			key:        "key",
			expiration: now.Add(time.Hour),
		})
	}
	cache.cache.Wait()

	retained := 0
	for i := range defaultMaxKeyCacheSize * 2 {
		if _, ok := cache.cache.Get(strconv.Itoa(i)); ok {
			retained++
		}
	}
	require.LessOrEqual(t, retained, defaultMaxKeyCacheSize)
}

func TestKeyCacheReloadUsesCachedValues(t *testing.T) {
	now := time.Unix(1000, 0)
	stats := &statRecorder{}
	transport := &recordingTransport{responses: []roundTripResponse{{body: "remote"}}}
	cache := newTestKeyCache(t, now, transport, stats.record)
	cache.storeKey("fresh", keyExpirationPair{key: "cached", expiration: now.Add(time.Minute)})
	cache.storeLookupMiss("missing", lookupMissError{error: errors.New("missing")})
	cache.cache.Wait()

	value, err := cache.reload("fresh")
	require.NoError(t, err)
	require.Equal(t, "cached", value)
	require.Equal(t, 0, transport.requestCount())
	require.Equal(t, float64(1), stats.get(statCacheRefreshSuccess))

	value, err = cache.reload("missing")
	require.Nil(t, value)
	_, ok := err.(lookupMissError)
	require.True(t, ok)
	require.Equal(t, 0, transport.requestCount())
}

func TestKeyCacheReloadFetchesAndStoresResults(t *testing.T) {
	now := time.Unix(1000, 0)
	stats := &statRecorder{}
	transport := &recordingTransport{
		responses: []roundTripResponse{{
			header: http.Header{"Cache-Control": {"max-age=60"}},
			body:   "remote",
		}},
	}
	cache := newTestKeyCache(t, now, transport, stats.record)

	value, err := cache.reload("kid")

	require.NoError(t, err)
	require.Equal(t, "remote", value)
	require.Equal(t, float64(1), stats.get(statCacheForceReload))
	entry, ok := cache.cache.Get("kid")
	require.True(t, ok)
	require.Equal(t, cacheEntryKey, entry.kind)
	require.Equal(t, "remote", entry.key)
	require.Equal(t, 1, transport.requestCount())
}

func TestKeyCacheReloadStoresLookupMiss(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &recordingTransport{
		responses: []roundTripResponse{
			{statusCode: http.StatusNotFound, body: "missing"},
			{header: http.Header{"Cache-Control": {"max-age=60"}}, body: "remote"},
		},
	}
	cache := newTestKeyCache(t, now, transport, nil)
	currentTime := now
	cache.timeNow = func() time.Time { return currentTime }

	value, err := cache.reload("kid")
	require.Nil(t, value)
	_, ok := err.(lookupMissError)
	require.True(t, ok)
	entry, ok := cache.cache.Get("kid")
	require.True(t, ok)
	require.Equal(t, cacheEntryLookupMiss, entry.kind)
	require.Equal(t, now.Add(20*time.Second), entry.freshUntil)
	require.Equal(t, now.Add(20*time.Second), entry.staleUntil)

	currentTime = now.Add(19 * time.Second)
	value, err = cache.reload("kid")
	require.Nil(t, value)
	_, ok = err.(lookupMissError)
	require.True(t, ok)
	require.Equal(t, 1, transport.requestCount())

	currentTime = now.Add(20 * time.Second)
	value, err = cache.reload("kid")
	require.NoError(t, err)
	require.Equal(t, "remote", value)
	require.Equal(t, 2, transport.requestCount())
}

func TestKeyCacheReloadSuppressesDuplicateReloads(t *testing.T) {
	now := time.Unix(1000, 0)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	transport := &recordingTransport{
		responses: []roundTripResponse{{
			header:  http.Header{"Cache-Control": {"max-age=60"}},
			body:    "remote",
			started: started,
			block:   release,
		}},
	}
	cache := newTestKeyCache(t, now, transport, nil)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	values := make(chan any, 10)
	wg.Go(func() {
		value, err := cache.reload("kid")
		errs <- err
		values <- value
	})
	<-started
	for i := 1; i < 10; i++ {
		wg.Go(func() {
			value, err := cache.reload("kid")
			errs <- err
			values <- value
		})
	}

	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	close(values)

	for err := range errs {
		require.NoError(t, err)
	}
	for value := range values {
		require.Equal(t, "remote", value)
	}
	require.Equal(t, 1, transport.requestCount())
}

func TestKeyCacheReloadsDifferentKeysConcurrently(t *testing.T) {
	startedFirst := make(chan struct{}, 1)
	startedSecond := make(chan struct{}, 1)
	releaseFirst := make(chan struct{})
	var release sync.Once
	unblockFirst := func() { release.Do(func() { close(releaseFirst) }) }
	defer unblockFirst()

	transport := &recordingTransport{responses: []roundTripResponse{
		{body: "first", started: startedFirst, block: releaseFirst},
		{body: "second", started: startedSecond},
	}}
	cache := newTestKeyCache(t, time.Unix(1000, 0), transport, nil)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Go(func() {
		_, err := cache.reload("first")
		errs <- err
	})
	<-startedFirst
	wg.Go(func() {
		_, err := cache.reload("second")
		errs <- err
	})

	select {
	case <-startedSecond:
	case <-time.After(time.Second):
		t.Fatal("reload for a different key was serialized")
	}
	unblockFirst()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestKeyCacheRefreshStaleSkipsUnrefreshableEntries(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &recordingTransport{responses: []roundTripResponse{{body: "remote"}}}
	cache := newTestKeyCache(t, now, transport, nil)

	cache.refreshStale("missing")
	cache.storeLookupMiss("lookup-miss", lookupMissError{error: errors.New("missing")})
	cache.storeKey("fresh", keyExpirationPair{key: "fresh", expiration: now.Add(time.Minute)})
	cache.storeKey("too-old", keyExpirationPair{key: "too-old", expiration: now.Add(-2 * time.Minute), staleWhileRevalidate: time.Minute})
	cache.cache.Wait()
	cache.refreshStale("lookup-miss")
	cache.refreshStale("fresh")
	cache.refreshStale("too-old")

	require.Equal(t, 0, transport.requestCount())
}

func TestKeyCacheRefreshStaleStoresFreshKey(t *testing.T) {
	now := time.Unix(1000, 0)
	stats := &statRecorder{}
	transport := &recordingTransport{
		responses: []roundTripResponse{{
			header: http.Header{"Cache-Control": {"max-age=60"}},
			body:   "refreshed",
		}},
	}
	cache := newTestKeyCache(t, now, transport, stats.record)
	cache.storeKey("kid", keyExpirationPair{key: "stale", expiration: now.Add(-time.Second), staleWhileRevalidate: time.Minute})
	cache.cache.Wait()

	cache.refreshStale("kid")

	entry, ok := cache.cache.Get("kid")
	require.True(t, ok)
	require.Equal(t, cacheEntryKey, entry.kind)
	require.Equal(t, "refreshed", entry.key)
	require.Equal(t, float64(1), stats.get(statCacheForceReload))
	require.Equal(t, 1, transport.requestCount())
}

func TestKeyCacheRefreshStaleHandlesLookupMiss(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &recordingTransport{
		responses: []roundTripResponse{{statusCode: http.StatusNotFound, body: "missing"}},
	}
	cache := newTestKeyCache(t, now, transport, nil)
	cache.storeKey("kid", keyExpirationPair{key: "stale", expiration: now.Add(-time.Second), staleWhileRevalidate: time.Minute})
	cache.cache.Wait()

	cache.refreshStale("kid")

	entry, ok := cache.cache.Get("kid")
	require.True(t, ok)
	require.Equal(t, cacheEntryLookupMiss, entry.kind)
	require.Equal(t, now.Add(lookupMissTTL), entry.freshUntil)
	require.Equal(t, now.Add(lookupMissTTL), entry.staleUntil)
	require.Equal(t, 1, transport.requestCount())
}

func TestKeyCacheRefreshStalePurgesBadResponse(t *testing.T) {
	now := time.Unix(1000, 0)
	transport := &recordingTransport{
		responses: []roundTripResponse{{body: "bad"}},
	}
	keyStore, err := newKeyStoreClient("http://keys.example", &http.Client{Transport: transport}, parseFailure)
	require.NoError(t, err)
	keyStore.timeNow = func() time.Time { return now }
	cache, err := newKeyCache(keyStore, nil)
	require.NoError(t, err)
	cache.timeNow = func() time.Time { return now }
	defer cache.close()
	cache.storeKey("kid", keyExpirationPair{key: "stale", expiration: now.Add(-time.Second), staleWhileRevalidate: time.Minute})
	cache.cache.Wait()

	cache.refreshStale("kid")

	_, ok := cache.cache.Get("kid")
	require.False(t, ok)
	require.Equal(t, 1, transport.requestCount())
}
