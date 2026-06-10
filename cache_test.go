package asap

import (
	"context"
	"sync"
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

	cache := NewTokenCache(context.Background(), defaultMaxTokenCacheSize, eventsCB)
	cacheImpl, ok := cache.(*cachingToken)
	require.True(t, ok)
	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	cacheImpl.tokenCache.Wait()
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

	cache := NewTokenCache(context.Background(), defaultMaxTokenCacheSize, eventsCB)
	cacheImpl, ok := cache.(*cachingToken)
	require.True(t, ok)
	token := makeToken("key", time.Now().Add(time.Minute))
	cache.Store("key", token)
	cacheImpl.tokenCache.Wait()
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

	cache := NewTokenCache(context.Background(), defaultMaxTokenCacheSize, eventsCB)
	cacheImpl, ok := cache.(*cachingToken)
	require.True(t, ok)
	token := makeToken("key", time.Now().Add(time.Second))
	cache.Store("key", token)
	cacheImpl.tokenCache.Wait()
	time.Sleep(time.Second)
	tk := cache.Get("key")
	assert.Nil(t, tk)
	wg.Wait()
}

func TestSizeLimit(t *testing.T) {
	t.Parallel()
	cache := NewTokenCache(context.Background(), 2, nil)

	cacheImpl, ok := cache.(*cachingToken)
	require.True(t, ok)

	for _, key := range []string{"key", "key2", "key3"} {
		cache.Store(key, makeToken(key, time.Now().Add(time.Minute)))
	}
	cacheImpl.tokenCache.Wait()

	var cached int
	for _, key := range []string{"key", "key2", "key3"} {
		if cache.Get(key) != nil {
			cached++
		}
	}
	require.Less(t, cached, 3)
}
