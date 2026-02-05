package asap

import (
	"sync"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheProvisionerWhenNil(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	require.Nilf(t, cache.cache, "Expected the cache to start as nil but found %s", cache.cache)
	var token, e = cache.Provision()
	require.NoError(t, e, "Got unexpected error provisioning a token")
	assert.Equal(t, cache.cache, token, "Expected the cache to store the provisioned token")
}

func TestCacheProvisionerReturnsCache(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	var token, e = cache.Provision()
	require.NoError(t, e, "Got unexpected error provisioning a token")
	var token2, e2 = cache.Provision()
	require.NoError(t, e2, "Got unexpected error provisioning a token")
	assert.Equal(t, token, token2, "Expected the cached token to be returned")
}

func TestCacheProvisionerExpired(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	var token, e = cache.Provision()
	require.NoError(t, e, "Got unexpected error provisioning a token")
	cache.cache.Claims().SetExpiration(time.Now().Add(-1 * time.Hour))
	var token2, e2 = cache.Provision()
	require.NoError(t, e2, "Got unexpected error provisioning a token")
	assert.NotEqual(t, token, token2, "Expected a new token to be returned")
}

func TestCacheProvisionerAlmostExpired(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	_, _ = cache.Provision()
	cache.cache.Claims().SetExpiration(time.Now().Add(2 * time.Second)) // about to expire, but still valid
	var token, e = cache.Provision()
	require.NoError(t, e, "Got unexpected error provisioning a token")
	time.Sleep(1 * time.Second) // enter expiration buffer
	var token2, e2 = cache.Provision()
	require.NoError(t, e2, "Got unexpected error provisioning a token")
	assert.NotEqual(t, token, token2, "Expected a new token to be returned")
}

func TestCacheProvisionerGenerationRace(t *testing.T) {
	t.Parallel()
	type testcase struct {
		name  string
		setup func(testName string, cache *cacheProvisioner)
	}
	var testcases = []testcase{
		{
			name: "nil cache race",
			setup: func(testName string, cache *cacheProvisioner) {
				require.Nilf(t, cache.cache, "%s: Expected the cache to start as nil", testName)
			},
		}, {
			name: "token near expiry race",
			setup: func(testName string, cache *cacheProvisioner) {
				_, _ = cache.Provision()
				cache.cache.Claims().SetExpiration(time.Now().Add(-1 * time.Hour))
			},
		},
	}

	for _, tc := range testcases {
		var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
		var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)

		tc.setup(tc.name, cache)

		wg := &sync.WaitGroup{}
		wg.Add(2)
		var token1, token2 Token
		provision := func(token *Token) {
			defer wg.Done()
			var e error
			*token, e = cache.Provision()
			require.NoError(t, e)
		}
		// Acquire write lock to block read lock (and following write lock) in Provision calls
		cache.lock.Lock()
		go provision(&token1) // nolint staticcheck
		go provision(&token2) // nolint staticcheck
		// Allow provision funcs to proceed to where read lock acquired, then unblock them
		time.Sleep(time.Millisecond)
		cache.lock.Unlock()
		wg.Wait()

		jti1 := token1.Claims()["jti"]
		jti2 := token2.Claims()["jti"]
		assert.Equalf(t, jti1, jti2, "%s: Expected identical tokens but found", tc.name)
	}
}

func TestCacheToken(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped)
	var token, e = cache.Provision()
	require.NoError(t, e)
	var key, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var b []byte
	b, e = token.(*cacheToken).Serialize(key)
	require.NoError(t, e)
	var b2 []byte
	b2, e = token.Serialize(key)
	require.NoError(t, e)
	assert.Equal(t, b, b2, "did not return a cached, signed token value")
}
