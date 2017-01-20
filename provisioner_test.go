package asap

import (
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

func TestCacheProvisionerWhenNil(t *testing.T) {
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
