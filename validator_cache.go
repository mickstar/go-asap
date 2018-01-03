package asap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type asapIssuerValidator struct{}

// Set an upper limit to prevent rogue issuers from chewing up all memory
// Assuming each token is ~1k, this will take ~100mb => not bad
const defaultMaxTokenCacheSize = 100000

func (v asapIssuerValidator) Validate(token Token) error {
	if token == nil {
		return errors.New("nil token")
	}

	issuer, ok := token.Claims().Get(ClaimIssuer).(string)
	if !ok || issuer == "" {
		return errors.New("missing or invalid issuer")
	}

	return nil
}

// CachingChainedASAPValidatorEvent defines a type to represent different events from the cache
type CachingChainedASAPValidatorEvent int

const (
	// CachingChainedASAPValidatorEventNone is default uninitialized state
	CachingChainedASAPValidatorEventNone CachingChainedASAPValidatorEvent = iota

	// CachingChainedASAPValidatorEventHit denotes a cache hit event
	CachingChainedASAPValidatorEventHit

	// CachingChainedASAPValidatorEventMiss denotes a cache miss
	CachingChainedASAPValidatorEventMiss

	// CachingChainedASAPValidatorEventPurge denotes a cache purge
	CachingChainedASAPValidatorEventPurge
)

// CachingChainedASAPValidatorCallBack defines type for a callback function to get notified on
// various cache events
type CachingChainedASAPValidatorCallBack func(CachingChainedASAPValidatorEvent)

// cachingChainedASAPValidator supports caching valid ASAP tokens with their expiration
// Helps reduce CPU utilization under load by not having to validate tokens that are valid
type cachingChainedASAPValidator struct {
	validators Validator

	purge             chan struct{}
	callbackFunc      CachingChainedASAPValidatorCallBack
	tokenCache        sync.Map
	tokenCacheSize    int64
	maxTokenCacheSize int64
}

// NewCachingChainedASAPValidator returns an instance of caching chained validators
func NewCachingChainedASAPValidator(ctx context.Context, maxTokenCacheSize int64,
	callbackFunc CachingChainedASAPValidatorCallBack, vs ...Validator) Validator {
	c := &cachingChainedASAPValidator{
		purge:             make(chan struct{}, 1),
		callbackFunc:      callbackFunc,
		validators:        NewValidatorChain(vs...),
		maxTokenCacheSize: maxTokenCacheSize,
	}

	if c.maxTokenCacheSize == 0 {
		c.maxTokenCacheSize = defaultMaxTokenCacheSize
	}

	// Initiate a background cleanup of expired cached entries
	go c.purgeStaleEntries(ctx)

	return c
}

// invokeCallBack is a helper function to relay cache events
func (v *cachingChainedASAPValidator) invokeCallBack(e CachingChainedASAPValidatorEvent) {
	if v.callbackFunc != nil {
		v.callbackFunc(e)
	}
}

// purgeStaleEntries clears up expired tokens using a 5 minute timer
func (v *cachingChainedASAPValidator) purgeStaleEntries(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			break
		case <-v.purge:
			break
		case <-ctx.Done():
			return
		}

		// Visit all entries in the cache and check for expired tokens & delete
		v.tokenCache.Range(func(key, value interface{}) bool {
			if expiration, ok := value.(time.Time); !ok || expiration.Before(time.Now()) {
				v.tokenCache.Delete(key)
				atomic.AddInt64(&v.tokenCacheSize, -1)
			}

			return true
		})

		// If a callback is registered, invoke it
		go v.invokeCallBack(CachingChainedASAPValidatorEventPurge)
	}
}

func (v *cachingChainedASAPValidator) Validate(token Token) error {
	// Check if we have the ASAP in our cache
	if token != nil {
		if val, ok := v.tokenCache.Load(token); ok {
			// Fetch the token expiration from cache for the token
			if cachedTokenExpiration, ok := val.(time.Time); ok {
				// Check if token in cache is still valid
				if cachedTokenExpiration.After(time.Now()) {
					go v.invokeCallBack(CachingChainedASAPValidatorEventHit)
					return nil
				}

				// If the token has expired, evict it from cache
				v.tokenCache.Delete(token)
				atomic.AddInt64(&v.tokenCacheSize, -1)
			}
		}

		go v.invokeCallBack(CachingChainedASAPValidatorEventMiss)
	}

	// Validate the ASAP token across registered validators - let them handle nil token
	if err := v.validators.Validate(token); err != nil {
		return err
	}

	// If token is nil, nothing much to cache
	if token == nil {
		return nil
	}

	// Do we have a token that has not yet expired
	expiration, _ := token.Claims().Expiration()
	if expiration.After(time.Now()) {
		// Check if we have enough room to cache the token
		if atomic.LoadInt64(&v.tokenCacheSize) < v.maxTokenCacheSize {
			v.tokenCache.Store(token, expiration)
			atomic.AddInt64(&v.tokenCacheSize, 1)
		} else if len(v.purge) < cap(v.purge) {
			// Initiate a purge of stale entries to make room in the background
			var trigger struct{}
			v.purge <- trigger
		}
	}

	return nil
}
