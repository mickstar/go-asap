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
	issuer, ok := token.Claims().Get(ClaimIssuer).(string)
	if !ok || issuer == "" {
		return errors.New("missing or invalid issuer")
	}
	return nil
}

// cachingChainedASAPValidator supports caching valid ASAP tokens with their expiration
// Helps reduce CPU utilization under load by not having to validate tokens that are valid
type cachingChainedASAPValidator struct {
	validators Validator

	purge             chan bool
	tokenCache        sync.Map
	tokenCacheSize    int64
	maxTokenCacheSize int64
}

// NewCachingChainedASAPValidator returns an instance of caching chained validators
func NewCachingChainedASAPValidator(ctx context.Context, maxTokenCacheSize int64, vs ...Validator) Validator {
	c := &cachingChainedASAPValidator{
		purge:             make(chan bool, 1),
		validators:        NewValidatorChain(vs...),
		maxTokenCacheSize: maxTokenCacheSize,
	}

	if c.maxTokenCacheSize == 0 {
		c.maxTokenCacheSize = defaultMaxTokenCacheSize
	}

	// Initiate a background cleanup of expired cached entries
	go c.Purge(ctx)

	return c
}

// Purge clears up expired tokens using a 5 minute timer
func (v *cachingChainedASAPValidator) Purge(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			v.purge <- true
		case <-v.purge:
			// Visit all entries in the cache and check for expired tokens & delete
			v.tokenCache.Range(func(key, value interface{}) bool {
				if expiration, ok := value.(time.Time); !ok || expiration.Before(time.Now()) {
					v.tokenCache.Delete(key)
					atomic.AddInt64(&v.tokenCacheSize, -1)
				}

				return true
			})
		case <-ctx.Done():
			break
		}
	}
}

func (v *cachingChainedASAPValidator) Validate(token Token) error {
	// Check if we have the ASAP in our cache
	if val, ok := v.tokenCache.Load(token); ok {
		// Fetch the token expiration from cache for the token
		if cachedTokenExpiration, ok := val.(time.Time); ok {
			// Check if token in cache is still valid
			if cachedTokenExpiration.After(time.Now()) {
				return nil
			}

			// If the token has expired, evict it from cache
			v.tokenCache.Delete(token)
			atomic.AddInt64(&v.tokenCacheSize, -1)
		}
	}

	// Validate the ASAP token across registered validators
	if err := v.validators.Validate(token); err != nil {
		return err
	}

	// Cache valid tokens only
	if token != nil {
		// Check if we have enough room to cache the token
		if atomic.LoadInt64(&v.tokenCacheSize) < v.maxTokenCacheSize {
			expiration, _ := token.Claims().Expiration()
			v.tokenCache.Store(token, expiration)
			atomic.AddInt64(&v.tokenCacheSize, 1)
		} else if len(v.purge) < cap(v.purge) {
			// Initiate a purge of stale entries to make room in the background
			v.purge <- true
		}
	}

	return nil
}
