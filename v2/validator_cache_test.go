package asap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func TestValidatorCacheChainRunsAll(t *testing.T) {
	t.Parallel()
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

func TestValidatorCacheValidateLimit(t *testing.T) {
	t.Parallel()
	var validator = func(Token) error {
		return nil
	}

	cache := NewCachingChainedASAPValidator(context.Background(), 2, nil, validatorFunc(validator), validatorFunc(validator))
	require.NotNil(t, cache)

	cacheImpl, ok := cache.(*cachingChainedASAPValidator)
	require.True(t, ok)

	tokens := []Token{
		makeToken("t1", time.Now().Add(time.Minute)),
		makeToken("t2", time.Now().Add(time.Minute)),
		makeToken("t3", time.Now().Add(time.Minute)),
	}
	for _, token := range tokens {
		require.NoError(t, cache.Validate(token))
	}
	cacheImpl.tokenCache.Wait()

	var cached int
	for _, token := range tokens {
		cacheableToken, ok := token.(CacheableKeyer)
		require.True(t, ok)
		if _, found := cacheImpl.tokenCache.Get(cacheableToken.CacheKey()); found {
			cached++
		}
	}
	require.LessOrEqual(t, cached, int(cacheImpl.maxTokenCacheSize))
}
