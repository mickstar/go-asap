package asap

import (
	"net/http"
	"net/textproto"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

const privateKeyTransport = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAzIXNCB3YktXiCiXiN1yRW+Ox9IqN2aenMKG9NHdOBlwp/2BQ
km+G4nRjkdfn+6XnmrLeLS6dA/gTj03tJ3YNJoqkjAcL2+x0SU3PtDYJO29TFOvI
Wlq2iJyTukYdlSXLhY5U3hyv/BdgI9gd6D2Tc6sy9i3CnkKSBlPniRQC2bor5ZzC
Lxr7NWMfe1HsAQExw6+iGwVtaNjP4wX2kMzAw6cPNYKsZqpjXx8/GzkralkXZvBh
W6IvVQe4EZjZW8MSoK7Gb6IAV+BM0ltOasY7OOPQvTjL/3Aj0KJSAjrpbdFzYzwp
IqUpwYFKW53y9eBnd2QlarrOnOGsdRBbCctV2QIDAQABAoIBACc4oZEk6BuAmNCJ
Y1BqmBWfHMlgqMNMu2tAGSCuoG/nzMYEmm76pEtZNp8JYJuJvViVZLYVclcIg/e/
YfNnWC5D+DpCP6v1NHe6TFKq6ipTtwMUFF//dXHNVScruxCXJuh92xidN8KIWQ+G
qnWXGWfdNPCw5dmjuo0sGgLXq5RFH4zKQJKVYB2t6E//PJsG5ultPUDl/+WgWOHe
+zq1U7r0bnQlqaZtzEhgJP0oQsuYKePWGcs8RpcKV3fTTY30HHIYKog5JL1FMV1I
nudG6q6Tug/3OpV80wGZujTKAiQCuW6lcov2IhKdwxPMEReCqqd6jo2m+GRF8lbE
EpvPc2ECgYEA952raix8lDkU/6iY4sVJP85N/pDIedT2Juy/VD3MpO3fZiASQqoV
5L7l9E9eb5iJEdL+3nhFQeV2VEScFpBoY+xhIbab0gT9qm8dhjm8dllpamsLcKrs
PoGXbhwu+NcIHUizXwOGBaO6/i1FuTJ/rNSjsyYHthXYY9rCha2YJ3sCgYEA03KZ
kMhSvKMMAY50VsDHtk+StvgqW8tI3LxuIL3i+MtY/IERSwSd5AUqMPEQWKpRS5EC
q2+0jy5eFwFm5aQManac6FctWgcSkgq3lgEC4pTguLNFbASuFzRie1ALJZbZrwxh
VJp2r+pI3s61VeGcU3FFSye+itrUBqxsmolLzbsCgYBM3mSNZFwUQ5gyOaukkmxH
44qw4U9rCuKTeOF4jGrQNIwqjwA8M8LyLRUD//OoHylGIENA2wNdDpfqVxZBpvjR
NFt+9Mpwq134H+CBf8Dy2JTyFWMKyfTm/qH868DlPRPmy1/ruhNMAuUU7Qb9FCEw
jR54ifDQ5P01Gn9Ssm5OqwKBgHkD6afXPqL/net2IFdWVfadbBaTyYpnufe7UDwk
8TX7C57YL5GDvum1mwQPs49LSuO4xpJfiDM6EleQUde0H/b+k6bV3frceWBkCdYs
Ff6fvk13LJA5zXkyXfq9QOPuhf+NUlcdYDgmGjaKj3XrfZC0DziIMqE9xINdQ3re
gSfpAoGAFvrknxQiS+c9IUGhjPbjJlLWkJwPKRyU20kTpvQGgmncrbLvY5vCeFla
b2zIosCQoyjL2ld2JHUHk/JUrSOXAHWbRFIJv5kExrJUws//wXtWDFtVnz9fs1Im
DKt9oGANzzAbRMfur9rydmujGR/TNkbkAWXI4g/toIiLlxlDQX8=
-----END RSA PRIVATE KEY-----
`

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
	var pk, _ = NewPrivateKey([]byte(privateKey))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	client.RoundTrip(r)
}

func TestTransportDecoratorHeadersDontDuplicate(t *testing.T) {
	t.Parallel()
	var provisioner = NewProvisioner("TEST", time.Hour, "TEST", []string{"TEST"}, crypto.SigningMethodRS256)
	var pk, _ = NewPrivateKey([]byte(privateKey))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	client.RoundTrip(r)
	client.RoundTrip(r)
	client.RoundTrip(r)
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
	var pk, _ = NewPrivateKey([]byte(privateKey))
	var client = NewTransportDecorator(provisioner, pk)(&asapDecoratorRoundTripper{t})
	var r, _ = http.NewRequest("GET", "/", nil)
	_, err := client.RoundTrip(r)

	switch err.(type) {
	case testerr:
	// worked
	default:
		t.Fatalf("Expected error %v got %v", testerr{}, err)
	}
}
