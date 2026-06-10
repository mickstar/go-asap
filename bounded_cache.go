package asap

import (
	"fmt"
	"time"

	"github.com/dgraph-io/ristretto/v2"
)

const ristrettoBufferItems = 64

func newBoundedCache[V any](maxItems int64) (*ristretto.Cache[string, V], error) {
	if maxItems <= 0 {
		return nil, fmt.Errorf("maxItems must be positive")
	}

	return ristretto.NewCache(&ristretto.Config[string, V]{
		NumCounters: maxItems * 10,
		MaxCost:     maxItems,
		BufferItems: ristrettoBufferItems,
	})
}

type boundedCache[V any] struct {
	cache *ristretto.Cache[string, V]
}

func newBoundedCacheWrapper[V any](maxItems int64) (*boundedCache[V], error) {
	cache, err := newBoundedCache[V](maxItems)
	if err != nil {
		return nil, err
	}
	return &boundedCache[V]{cache: cache}, nil
}

func (c *boundedCache[V]) Get(key string) (V, bool) {
	return c.cache.Get(key)
}

func (c *boundedCache[V]) SetWithTTL(key string, value V, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	return c.cache.SetWithTTL(key, value, 1, ttl)
}
func (c *boundedCache[V]) Del(key string) {
	c.cache.Del(key)
}

func (c *boundedCache[V]) Wait() {
	c.cache.Wait()
}

func (c *boundedCache[V]) Close() {
	c.cache.Close()
}
