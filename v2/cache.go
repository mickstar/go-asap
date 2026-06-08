package asap

import (
	"context"
	"log"
	"time"
)

// CachingTokenEvent defines a type to represent different events from the cache
type CachingTokenEvent int

const (
	// CachingTokenEventNone is default uninitialized state
	CachingTokenEventNone CachingTokenEvent = iota

	// CachingTokenEventHit denotes a cache hit event
	CachingTokenEventHit

	// CachingTokenEventMiss denotes a cache miss
	CachingTokenEventMiss
)

// TokenCache is a higher level ASAP token cache
type TokenCache interface {
	Get(string) Token
	Store(string, Token)
}

// CachingTokenCallBack defines type for a callback function to get notified on
// various cache events
type CachingTokenCallBack func(CachingTokenEvent)

// CachingToken caches parsed tokens in memory
// Can be used on ingress to avoid parsing tokens & validating them if reused
// Can be used on egress to reuse tokens
type tokenCacheEntry struct {
	token     Token
	expiresAt time.Time
}

type cachingToken struct {
	callbackFunc      CachingTokenCallBack
	tokenCache        *boundedCache[tokenCacheEntry]
	maxTokenCacheSize int64
}

// NewTokenCache returns a token cache
func NewTokenCache(ctx context.Context, maxTokenCacheSize int64,
	callbackFunc CachingTokenCallBack) TokenCache {
	if maxTokenCacheSize == 0 {
		maxTokenCacheSize = defaultMaxTokenCacheSize
	}

	tokenCache, err := newBoundedCacheWrapper[tokenCacheEntry](maxTokenCacheSize)
	if err != nil {
		tokenCache = nil
	}

	c := &cachingToken{
		callbackFunc:      callbackFunc,
		tokenCache:        tokenCache,
		maxTokenCacheSize: maxTokenCacheSize,
	}

	return c
}

// invokeCallBack is a helper function to relay cache events
func (v *cachingToken) invokeCallBack(e CachingTokenEvent) {
	if v.callbackFunc == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("asap: token cache callback failed for event %d: %v", e, recovered)
		}
	}()
	v.callbackFunc(e)
}

func (v *cachingToken) Get(token string) Token {
	if v.tokenCache != nil {
		if entry, ok := v.tokenCache.Get(token); ok {
			if entry.expiresAt.After(time.Now()) {
				v.invokeCallBack(CachingTokenEventHit)
				return entry.token
			}
			v.tokenCache.Del(token)
		}
	}

	v.invokeCallBack(CachingTokenEventMiss)
	return nil
}

func (v *cachingToken) Store(jwt string, token Token) {
	if v.tokenCache == nil {
		return
	}

	expiration, ok := token.Claims().Expiration()
	if !ok {
		return
	}

	v.tokenCache.SetWithTTL(jwt, tokenCacheEntry{token: token, expiresAt: expiration}, time.Until(expiration))
}
