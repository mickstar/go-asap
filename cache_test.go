package asap

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuccessfulGet(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(1)
	eventsCB := func(e CachingTokenEvent) {
		assert.Equal(t, e, CachingTokenEventHit)
		wg.Done()
	}

	cache := NewTokenCache(context.Background(), 2, eventsCB)
	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	tk := cache.Get("key")
	assert.Equal(t, token, tk)
	wg.Wait()
}

func TestMiss(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(1)
	eventsCB := func(e CachingTokenEvent) {
		assert.Equal(t, e, CachingTokenEventMiss)
		wg.Done()
	}

	cache := NewTokenCache(context.Background(), 2, eventsCB)
	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	tk := cache.Get("other-key")
	assert.Nil(t, tk)
	wg.Wait()
}

func TestExpire(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(1)
	eventsCB := func(e CachingTokenEvent) {
		assert.Equal(t, e, CachingTokenEventMiss)
		wg.Done()
	}

	cache := NewTokenCache(context.Background(), 2, eventsCB)
	token := makeToken("key", time.Now().Add(time.Second))
	cache.Store("key", token)
	time.Sleep(time.Second)
	tk := cache.Get("key")
	assert.Nil(t, tk)
	wg.Wait()
}

func TestPurge(t *testing.T) {
	t.Parallel()
	var ok bool
	var cacheImpl *cachingToken

	var wg sync.WaitGroup
	wg.Add(1)
	eventsCB := func(e CachingTokenEvent) {
		if e == CachingTokenEventPurge {
			require.Equal(t, int64(0), atomic.LoadInt64(&cacheImpl.tokenCacheSize))
			wg.Done()
		}
	}

	cache := NewTokenCache(context.Background(), 2, eventsCB)
	cacheImpl, ok = cache.(*cachingToken)
	require.True(t, ok)

	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	require.Equal(t, int64(1), atomic.LoadInt64(&cacheImpl.tokenCacheSize))

	time.Sleep(time.Second)

	var trigger struct{}
	cacheImpl.purge <- trigger

	wg.Wait()
}

func TestSizeLimit(t *testing.T) {
	t.Parallel()
	cache := NewTokenCache(context.Background(), 2, nil)

	cacheImpl, ok := cache.(*cachingToken)
	require.True(t, ok)

	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	require.Equal(t, int64(1), atomic.LoadInt64(&cacheImpl.tokenCacheSize))

	cache.Store("key2", token)
	require.Equal(t, int64(2), atomic.LoadInt64(&cacheImpl.tokenCacheSize))

	cache.Store("key3", token)
	require.Equal(t, int64(2), atomic.LoadInt64(&cacheImpl.tokenCacheSize))
}
