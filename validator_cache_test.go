package asap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func TestValidatorCacheChainRunsAll(t *testing.T) {
	var (
		counter   = 0
		validator = func(Token) error {
			counter++
			return nil
		}
		v = NewCachingChainedASAPValidator(context.Background(), 100, nil, validatorFunc(validator), validatorFunc(validator))
		e = v.Validate(nil)
	)

	if e != nil {
		t.Fatalf("Error testing validator chain: %s", e)
	}

	if counter != 2 {
		t.Fatalf("Expected 2 validator runs but saw %d", counter)
	}
}

func makeToken(key string, expiry time.Time) Token {
	privateKey, _ := rsa.GenerateKey(rand.Reader, minValidBits)
	claims := jws.Claims{}
	claims.Set(key, key)
	claims.SetExpiration(expiry)

	token := jws.NewJWT(claims, crypto.SigningMethodRS256)

	data, e := token.Serialize(privateKey)
	if e != nil {
		log.Fatalf("Failed to sign token: %s", e)
	}

	t, e := ParseToken(string(data))
	if e != nil {
		log.Fatalf("Failed to PARSE token: %s", e)
	}

	return t
}

func TestValidatorCacheValidatePurge(t *testing.T) {
	var ok bool
	var cacheImpl *cachingChainedASAPValidator
	var validator = func(Token) error {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	eventsCB := func(e CachingChainedASAPValidatorEvent) {
		// Since we inserted an expired token, the cache should be empty after Purge
		if e == CachingChainedASAPValidatorEventPurge {
			require.Equal(t, int64(0), cacheImpl.tokenCacheSize)
			wg.Done()
		}
	}

	cache := NewCachingChainedASAPValidator(context.Background(), 100, eventsCB, validatorFunc(validator), validatorFunc(validator))
	require.NotNil(t, cache)

	cacheImpl, ok = cache.(*cachingChainedASAPValidator)
	require.True(t, ok)

	t1 := makeToken("t1", time.Now().Add(time.Second))
	require.NotNil(t, t1)

	e := cache.Validate(t1)
	require.Nil(t, e)
	require.Equal(t, int64(1), cacheImpl.tokenCacheSize)

	// Ensure the entry in cache has expired
	time.Sleep(time.Second * 2)

	// Initiate a purge and ensure the expired entry is purged
	var trigger struct{}

	// Ensure a purge gets called before we check the cache by filling the purge request chan
	cacheImpl.purge <- trigger

	wg.Wait()
}

func TestValidatorCacheValidateLimit(t *testing.T) {
	var validator = func(Token) error {
		return nil
	}

	cache := NewCachingChainedASAPValidator(context.Background(), 2, nil, validatorFunc(validator), validatorFunc(validator))
	require.NotNil(t, cache)

	cacheImpl, ok := cache.(*cachingChainedASAPValidator)
	require.True(t, ok)

	t1 := makeToken("t1", time.Now().Add(time.Minute))
	require.NotNil(t, t1)

	// Add a token to the cache
	e := cache.Validate(t1)
	require.Nil(t, e)
	require.Equal(t, int64(1), cacheImpl.tokenCacheSize)

	t2 := makeToken("t2", time.Now().Add(time.Minute))
	require.NotNil(t, t2)

	e = cache.Validate(t2)
	require.Nil(t, e)
	require.Equal(t, int64(2), cacheImpl.tokenCacheSize)

	// Attempt adding more tokens than the max limit
	t3 := makeToken("t3", time.Now().Add(time.Minute))
	require.NotNil(t, t3)

	e = cache.Validate(t3)
	require.Nil(t, e)
	require.Equal(t, cacheImpl.maxTokenCacheSize, cacheImpl.tokenCacheSize)
}
