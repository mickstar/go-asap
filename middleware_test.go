package asap

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

type fixtureHandler struct {
	called bool
}

func (h *fixtureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
}

func TestMiddlewareHandlesInvalidBearer(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var fetcher = &fixtureFetcher{publicKey, nil}
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(fetcher, validator, callback)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", ioutil.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "TEST")
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject an invalid bearer")
	}
}

func TestMiddlewareHandlesInvalidTokens(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var fetcher = &fixtureFetcher{publicKey, nil}
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(fetcher, validator, callback)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", ioutil.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer TEST")
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject an invalid token")
	}
}

func TestMiddlewareHandlesValidationFailure(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var fetcher = &fixtureFetcher{publicKey, nil}
	var validator = validatorFunc(func(Token) error { return fmt.Errorf("") })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(fetcher, validator, callback)(wrapped)
	var token, _ = NewProvisioner("TEST/TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256).Provision()
	var pk, _ = NewPrivateKey([]byte(privateKey))
	var headerValue, _ = token.Serialize(pk)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", ioutil.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer "+string(headerValue))
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject a request that failed the validator")
	}
}

func TestMiddlewareHandlesAcceptsValidTokens(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var fetcher = &fixtureFetcher{publicKey, nil}
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(fetcher, DefaultValidator, callback)(wrapped)
	var token, _ = NewProvisioner("TEST/TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256).Provision()
	var pk, _ = NewPrivateKey([]byte(privateKey))
	var headerValue, _ = token.Serialize(pk)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", ioutil.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer "+string(headerValue))
	m.ServeHTTP(w, r)
	if calledCallback {
		t.Fatal("Middleware did not accept a valid token")
	}
}

func TestMiddlewareHandlesSends403ByDefault(t *testing.T) {
	var fetcher = &fixtureFetcher{publicKey, nil}
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(fetcher, validator, nil)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", ioutil.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "TEST")
	m.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("Middleware did not default toa 403 response.")
	}
}
