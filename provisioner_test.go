package asap

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

func TestCacheProvisionerWhenNil(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	if cache.cache != nil {
		t.Fatalf("Expected the cache to start as nil but found %s", cache.cache)
	}
	var token, e = cache.Provision()
	if e != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e)
	}
	if cache.cache != token {
		t.Fatalf("Expected the cache to store the provisioned token but found %s", cache.cache)
	}
}

func TestCacheProvisionerReturnsCache(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	var token, e = cache.Provision()
	if e != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e)
	}
	var token2, e2 = cache.Provision()
	if e2 != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e2)
	}
	if token != token2 {
		t.Fatalf("Expected the cached token to be returned but found %s %s", token, token2)
	}
}

func TestCacheProvisionerExpired(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	var token, e = cache.Provision()
	if e != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e)
	}
	cache.cache.Claims().SetExpiration(time.Now().Add(-1 * time.Hour))
	var token2, e2 = cache.Provision()
	if e2 != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e2)
	}
	if token == token2 {
		t.Fatalf("Expected a new token to be returned but found %s %s", token, token2)
	}
}

func TestCacheProvisionerAlmostExpired(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped).(*cacheProvisioner)
	_, _ = cache.Provision()
	cache.cache.Claims().SetExpiration(time.Now().Add(2 * time.Second)) // about to expire, but still valid
	var token, e = cache.Provision()
	if e != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e)
	}
	time.Sleep(1 * time.Second) // enter expiration buffer
	var token2, e2 = cache.Provision()
	if e2 != nil {
		t.Fatalf("Got unexpected error provisioning a token: %s", e2)
	}
	if token == token2 {
		t.Fatalf("Expected a new token to be returned but found %s %s", token, token2)
	}
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
				if cache.cache != nil {
					t.Fatalf("%s: Expected the cache to start as nil but found %s", testName, cache.cache)
				}
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
			if e != nil {
				t.Fatal(e.Error())
			}
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
		if jti1 != jti2 {
			t.Fatalf("%s: Expected identical tokens but found %s %s", tc.name, jti1, jti2)
		}
	}
}

func TestCacheToken(t *testing.T) {
	t.Parallel()
	var wrapped = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var cache = NewCachingProvisioner(wrapped)
	var token, e = cache.Provision()
	if e != nil {
		t.Fatal(e.Error())
	}
	var key, _ = NewPrivateKey([]byte(privateKey))
	var b []byte
	b, e = token.(*cacheToken).Serialize(key)
	if e != nil {
		t.Fatal(e.Error())
	}
	var b2 []byte
	b2, e = token.Serialize(key)
	if e != nil {
		t.Fatal(e.Error())
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("did not return a cached, signed token value")
	}
}
