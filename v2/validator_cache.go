package asap

import (
	"context"
	"log"
	"time"
)

// Set an upper limit to prevent rogue issuers from chewing up all memory
// Assuming each token is ~1k, this will take ~100mb => not bad
const defaultMaxTokenCacheSize = 100000

// CachingChainedASAPValidatorEvent defines a type to represent different events from the cache
type CachingChainedASAPValidatorEvent int

const (
	// CachingChainedASAPValidatorEventNone is default uninitialized state
	CachingChainedASAPValidatorEventNone CachingChainedASAPValidatorEvent = iota

	// CachingChainedASAPValidatorEventHit denotes a cache hit event
	CachingChainedASAPValidatorEventHit

	// CachingChainedASAPValidatorEventMiss denotes a cache miss
	CachingChainedASAPValidatorEventMiss
)

// CachingChainedASAPValidatorCallBack defines type for a callback function to get notified on
// various cache events
type CachingChainedASAPValidatorCallBack func(CachingChainedASAPValidatorEvent)

// cachingChainedASAPValidator supports caching valid ASAP tokens with their expiration
// Helps reduce CPU utilization under load by not having to validate tokens that are valid
type cachingChainedASAPValidator struct {
	validators Validator

	callbackFunc      CachingChainedASAPValidatorCallBack
	tokenCache        *boundedCache[time.Time]
	maxTokenCacheSize int64
}

// NewCachingChainedASAPValidator returns an instance of caching chained validators
func NewCachingChainedASAPValidator(ctx context.Context, maxTokenCacheSize int64,
	callbackFunc CachingChainedASAPValidatorCallBack, vs ...Validator) Validator {
	if maxTokenCacheSize == 0 {
		maxTokenCacheSize = defaultMaxTokenCacheSize
	}

	tokenCache, err := newBoundedCacheWrapper[time.Time](maxTokenCacheSize)
	if err != nil {
		tokenCache = nil
	}

	c := &cachingChainedASAPValidator{
		callbackFunc:      callbackFunc,
		validators:        NewValidatorChain(vs...),
		tokenCache:        tokenCache,
		maxTokenCacheSize: maxTokenCacheSize,
	}

	return c
}

// invokeCallBack is a helper function to relay cache events
func (v *cachingChainedASAPValidator) invokeCallBack(e CachingChainedASAPValidatorEvent) {
	if v.callbackFunc == nil {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("asap: validator cache callback failed for event %d: %v", e, recovered)
		}
	}()
	v.callbackFunc(e)
}

func (v *cachingChainedASAPValidator) Validate(token Token) error {
	cacheableToken, cacheable := token.(CacheableKeyer)
	if !cacheable {
		return v.validators.Validate(token)
	}

	if v.tokenCache != nil {
		if cachedTokenExpiration, found := v.tokenCache.Get(cacheableToken.CacheKey()); found {
			if cachedTokenExpiration.After(time.Now()) {
				v.invokeCallBack(CachingChainedASAPValidatorEventHit)
				return nil
			}
			v.tokenCache.Del(cacheableToken.CacheKey())
		}
	}

	v.invokeCallBack(CachingChainedASAPValidatorEventMiss)

	// Validate the ASAP token across registered validators - let them handle nil token
	if err := v.validators.Validate(token); err != nil {
		return err
	}

	if expiration, found := token.Claims().Expiration(); found && v.tokenCache != nil {
		v.tokenCache.SetWithTTL(cacheableToken.CacheKey(), expiration, time.Until(expiration))
	}

	return nil
}
