package asap

import (
	"net/http"
	"net/textproto"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

type asapDecoratorRoundTripper struct {
	t *testing.T
}

func (rt *asapDecoratorRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(r.Header.Get("Authorization")) < 1 {
		rt.t.Fatalf("Missing Authorization header.")
	}
	if r.Header.Get("Authorization")[len("Bearer "):] == "" {
		rt.t.Fatalf("Incorrect bearer token added: %s.", r.Header.Get("Authorization"))
	}
	return &http.Response{}, nil
}

func TestTransportDecoratorHeaders(t *testing.T) {
	t.Parallel()
	var provisioner = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var pk, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	_, _ = client.RoundTrip(r) //nolint bodyclose
}

func TestTransportDecoratorHeadersDontDuplicate(t *testing.T) {
	t.Parallel()
	var provisioner = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var pk, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	_, _ = client.RoundTrip(r) //nolint bodyclose
	_, _ = client.RoundTrip(r) //nolint bodyclose
	_, _ = client.RoundTrip(r) //nolint bodyclose
	if len(r.Header[textproto.CanonicalMIMEHeaderKey("Authorization")]) > 1 {
		t.Fatalf("expected only one header entry but found %d", len(r.Header[textproto.CanonicalMIMEHeaderKey("Authorization")]))
	}
}

type testerr struct{}

func (t testerr) Error() string {
	return "Test error"
}

type failingProvisioner struct{}

func (p *failingProvisioner) Provision() (Token, error) {
	return nil, testerr{}
}

func TestTransportDecoratorFailedTokenProvision(t *testing.T) {
	t.Parallel()
	var provisioner = &failingProvisioner{}
	var pk, _ = NewPrivateKey([]byte(privateKeyPKCS1RSA))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	_, err := client.RoundTrip(r) //nolint bodyclose

	switch err.(type) {
	case testerr:
	// worked
	default:
		t.Fatalf("Expected error %v got %v", testerr{}, err)
	}
}
