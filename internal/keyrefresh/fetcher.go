package keyrefresh

import (
	"fmt"
	"net/http"
	"sync"
)

const (
	defaultQueueSize = 1024

	statCachedKey           = "asap.key.cache.hit"
	statExpiredKey          = "asap.key.cache.expired"
	statCachedLookupMiss    = "asap.key.cache.lookup_miss"
	statCacheMiss           = "asap.key.cache.miss"
	statCacheRefreshSuccess = "asap.key.cache.refresh.success"
	statCacheForceReload    = "asap.key.cache.refresh.force_reload"
)

type Stats func(stat string, count float64, tags ...string)

type Config struct {
	BaseURL        string
	HTTPClient     *http.Client
	ParsePublicKey func([]byte) (any, error)
	Stats          Stats
	QueueSize      int
}

type Fetcher struct {
	keys      *keyCache
	queue     chan string
	stop      chan struct{}
	closeOnce sync.Once
}

func NewFetcher(config Config) (*Fetcher, error) {
	if config.ParsePublicKey == nil {
		return nil, fmt.Errorf("parse public key function is required")
	}
	queueSize := config.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}

	keyStore, err := newKeyStoreClient(config.BaseURL, config.HTTPClient, config.ParsePublicKey)
	if err != nil {
		return nil, err
	}
	keys, err := newKeyCache(keyStore, config.Stats)
	if err != nil {
		return nil, err
	}

	f := &Fetcher{
		keys:  keys,
		queue: make(chan string, queueSize),
		stop:  make(chan struct{}),
	}
	go f.run()
	return f, nil
}

func (f *Fetcher) Fetch(keyID string) (any, error) {
	value, ok := f.keys.cache.Get(keyID)
	if ok {
		now := f.keys.timeNow()
		switch value.kind {
		case cacheEntryLookupMiss:
			if value.freshUntil.After(now) {
				f.keys.incr(statCachedLookupMiss)
				return nil, value.lookupMiss
			}
		case cacheEntryKey:
			if value.freshUntil.After(now) {
				f.keys.incr(statCachedKey)
				return value.key, nil
			}
			if value.staleUntil.After(now) {
				f.enqueueRefresh(keyID)
				f.keys.incr(statExpiredKey)
				return value.key, nil
			}
		}
	}

	f.keys.incr(statCacheMiss)
	return f.keys.reload(keyID)
}

func (f *Fetcher) enqueueRefresh(keyID string) {
	select {
	case f.queue <- keyID:
	default:
	}
}

func (f *Fetcher) run() {
	for {
		select {
		case <-f.stop:
			return
		case keyID := <-f.queue:
			f.keys.refreshStale(keyID)
		}
	}
}

func (f *Fetcher) Close() error {
	f.closeOnce.Do(func() {
		close(f.stop)
	})
	f.keys.close()
	return nil
}
