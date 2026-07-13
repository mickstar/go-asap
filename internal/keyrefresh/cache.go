package keyrefresh

import (
	"crypto"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/sync/singleflight"
)

const (
	defaultMaxKeyCacheSize = 10000
	ristrettoBufferItems   = 64
	lookupMissTTL          = time.Second
)

type keyExpirationPair struct {
	key                  crypto.PublicKey
	expiration           time.Time
	staleWhileRevalidate time.Duration
}

type cacheEntryKind string

const (
	cacheEntryKey        cacheEntryKind = "key"
	cacheEntryLookupMiss cacheEntryKind = "lookup_miss"
)

type lookupError struct {
	error
}

type lookupMissError struct {
	error
}

type badResponseError struct {
	error
}

type keyCacheEntry struct {
	kind       cacheEntryKind
	key        crypto.PublicKey
	lookupMiss lookupMissError
	freshUntil time.Time
	staleUntil time.Time
}

func newKeyCacheEntry(pair keyExpirationPair) keyCacheEntry {
	return keyCacheEntry{
		kind:       cacheEntryKey,
		key:        pair.key,
		freshUntil: pair.expiration,
		staleUntil: pair.expiration.Add(pair.staleWhileRevalidate),
	}
}

func newKeyLookupMissCacheEntry(miss lookupMissError, expiration time.Time) keyCacheEntry {
	return keyCacheEntry{
		kind:       cacheEntryLookupMiss,
		lookupMiss: miss,
		freshUntil: expiration,
		staleUntil: expiration,
	}
}

type keyCache struct {
	reloads    singleflight.Group
	keyStore   *keyStoreClient
	cache      *ristretto.Cache[string, keyCacheEntry]
	cacheStats Stats
	timeNow    func() time.Time
}

func newKeyCache(keyStore *keyStoreClient, stats Stats) (*keyCache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, keyCacheEntry]{
		NumCounters: defaultMaxKeyCacheSize * 10,
		MaxCost:     defaultMaxKeyCacheSize,
		BufferItems: ristrettoBufferItems,
	})
	if err != nil {
		return nil, err
	}

	return &keyCache{
		keyStore:   keyStore,
		cache:      cache,
		cacheStats: stats,
		timeNow:    time.Now,
	}, nil
}

func (c *keyCache) incr(stat string) {
	if c.cacheStats == nil {
		return
	}

	c.cacheStats(stat, 1)
}

func (c *keyCache) reload(keyID string) (interface{}, error) {
	value, err, _ := c.reloads.Do(keyID, func() (interface{}, error) {
		return c.reloadOnce(keyID)
	})
	return value, err
}

func (c *keyCache) reloadOnce(keyID string) (interface{}, error) {
	if value, ok := c.cache.Get(keyID); ok {
		now := c.timeNow()
		switch value.kind {
		case cacheEntryLookupMiss:
			if value.freshUntil.After(now) {
				return nil, value.lookupMiss
			}
		case cacheEntryKey:
			if value.freshUntil.After(now) {
				c.incr(statCacheRefreshSuccess)
				return value.key, nil
			}
		}
	}

	result, err := c.keyStore.fetch(keyID)
	if err != nil {
		if v, ok := err.(lookupMissError); ok {
			c.storeLookupMiss(keyID, v)
			c.cache.Wait()
		}
		return nil, err
	}
	c.incr(statCacheForceReload)
	c.storeKey(keyID, result)
	c.cache.Wait()
	return result.key, nil
}

func (c *keyCache) refreshStale(keyID string) {
	value, ok := c.cache.Get(keyID)
	if !ok || value.kind != cacheEntryKey {
		return
	}

	now := c.timeNow()
	if value.freshUntil.After(now) || !value.staleUntil.After(now) {
		return
	}

	result, err := c.keyStore.fetch(keyID)
	if err != nil {
		if v, ok := err.(lookupMissError); ok {
			c.storeLookupMiss(keyID, v)
			c.cache.Wait()
		}
		if _, ok := err.(badResponseError); ok {
			c.cache.Del(keyID)
			c.cache.Wait()
		}
		return
	}
	c.incr(statCacheForceReload)
	c.storeKey(keyID, result)
	c.cache.Wait()
}

func (c *keyCache) close() {
	if c.cache != nil {
		c.cache.Close()
	}
}

func (c *keyCache) storeKey(keyID string, pair keyExpirationPair) {
	entry := newKeyCacheEntry(pair)
	c.storeEntry(keyID, entry)
}

func (c *keyCache) storeLookupMiss(keyID string, miss lookupMissError) {
	entry := newKeyLookupMissCacheEntry(miss, c.timeNow().Add(lookupMissTTL))
	c.storeEntry(keyID, entry)
}

func (c *keyCache) storeEntry(keyID string, entry keyCacheEntry) {
	ttl := entry.staleUntil.Sub(c.timeNow())
	if ttl <= 0 {
		return
	}
	c.cache.SetWithTTL(keyID, entry, 1, ttl)
}
