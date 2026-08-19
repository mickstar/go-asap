package asap

import (
	"bytes"
	"fmt"
	"io"
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
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(validator, callback)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", io.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "TEST")
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject an invalid bearer")
	}
}

func TestMiddlewareHandlesInvalidTokens(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(validator, callback)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", io.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer TEST")
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject an invalid token")
	}
}

func TestMiddlewareHandlesValidationFailure(t *testing.T) {
	var calledCallback = false
	var gotErrorType = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) {
		calledCallback = true
		var _, ok = e.(*FailedValidationError)
		gotErrorType = ok
	}
	var validator = validatorFunc(func(Token) error { return fmt.Errorf("") })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(validator, callback)(wrapped)
	var token, _ = NewProvisioner("TEST/TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256).Provision()
	var pk, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var headerValue, _ = token.Serialize(pk)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", io.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer "+string(headerValue))
	m.ServeHTTP(w, r)
	if !calledCallback {
		t.Fatal("Middleware did not reject a request that failed the validator")
	}
	if !gotErrorType {
		t.Fatal("Middleware did not emit a FailedValidationError")
	}
}

func TestMiddlewareHandlesAcceptsValidTokens(t *testing.T) {
	var calledCallback = false
	var callback = func(w http.ResponseWriter, r *http.Request, e error) { calledCallback = true }
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(DefaultValidator, callback)(wrapped)
	var token, _ = NewProvisioner("TEST/TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256).Provision()
	var pk, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var headerValue, _ = token.Serialize(pk)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", io.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "Bearer "+string(headerValue))
	m.ServeHTTP(w, r)
	if calledCallback {
		t.Fatal("Middleware did not accept a valid token")
	}
}

func TestMiddlewareHandlesSends403ByDefault(t *testing.T) {
	var validator = validatorFunc(func(Token) error { return nil })
	var wrapped = &fixtureHandler{}
	var m = NewMiddleware(validator, nil)(wrapped)

	var w = httptest.NewRecorder()
	var r, _ = http.NewRequest(http.MethodGet, "/", io.NopCloser(bytes.NewBufferString(``)))
	r.Header.Set("Authorization", "TEST")
	m.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Middleware did not default to a 401 response.")
	}
}
