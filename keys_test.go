package asap

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"
)

const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIXNCB3YktXiCiXiN1yR
W+Ox9IqN2aenMKG9NHdOBlwp/2BQkm+G4nRjkdfn+6XnmrLeLS6dA/gTj03tJ3YN
JoqkjAcL2+x0SU3PtDYJO29TFOvIWlq2iJyTukYdlSXLhY5U3hyv/BdgI9gd6D2T
c6sy9i3CnkKSBlPniRQC2bor5ZzCLxr7NWMfe1HsAQExw6+iGwVtaNjP4wX2kMzA
w6cPNYKsZqpjXx8/GzkralkXZvBhW6IvVQe4EZjZW8MSoK7Gb6IAV+BM0ltOasY7
OOPQvTjL/3Aj0KJSAjrpbdFzYzwpIqUpwYFKW53y9eBnd2QlarrOnOGsdRBbCctV
2QIDAQAB
-----END PUBLIC KEY-----
`

const privateKey = `-----BEGIN RSA PRIVATE KEY-----
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

type fixtureRoundTripper struct {
	response *http.Response
	e        error
	request  *http.Request
}

func (r *fixtureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.request = req
	return r.response, r.e
}

type fixtureFetcher struct {
	value interface{}
	e     error
}

func (f *fixtureFetcher) Fetch(string) (interface{}, error) {
	return f.value, f.e
}

func TestPrivateKeyParser(t *testing.T) {
	var _, e = NewPrivateKey([]byte(privateKey))
	if e != nil {
		t.Fatalf("Could not parse private key %s", e)
	}
}

func TestPublicKeyParser(t *testing.T) {
	var _, e = NewPublicKey([]byte(publicKey))
	if e != nil {
		t.Fatalf("Could not parse public key %s", e)
	}
}

func TestHTTPFetcherJoinsKidToPath(t *testing.T) {
	var response = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBufferString(``)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	var f = NewHTTPKeyFetcher("http://localhost", client)
	f.Fetch("TEST")
	if transport.request.URL.String() != "http://localhost/TEST" {
		t.Fatalf("HTTP fetcher did not use the key id in the path.")
	}
}

func TestHTTPFetcher(t *testing.T) {
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	var f = NewHTTPKeyFetcher("http://localhost", client)
	var _, e = f.Fetch("TEST")
	if e != nil {
		t.Fatalf("HTTP fetcher did not parse the response body.")
	}
}

func TestCacheFetcher(t *testing.T) {
	var value = "TEST"
	var kid = "keyID"
	var wrapped = &fixtureFetcher{value, nil}
	var f = NewCachingFetcher(wrapped).(*cacheFetcher)
	var k, _ = f.Fetch(kid)
	if k != value {
		t.Fatalf("Expected to get TEST but instead got %s", k)
	}
	if f.cache[kid] != value {
		t.Fatalf("Expected to find a cache entry but found %s", f.cache[kid])
	}

	wrapped.value = "TEST2"
	k, _ = f.Fetch(kid)
	if k != value {
		t.Fatalf("Expected to get the cached value but instead got %s", k)
	}
}

func TestMultiFetcherSuccess(t *testing.T) {
	var failure = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBufferString(``)),
	}
	var success = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var successClient = &http.Client{Transport: &fixtureRoundTripper{success, nil, nil}}
	var failureClient = &http.Client{Transport: &fixtureRoundTripper{failure, nil, nil}}

	var f = NewMultiFetcher(
		NewHTTPKeyFetcher("http://localhost", failureClient),
		NewHTTPKeyFetcher("http://localhost", successClient),
	)
	_, e := f.Fetch("TEST")
	if e != nil {
		t.Fatalf("MultiFetcher fetcher did not parse the response body.")
	}
}

func TestMultiFetcherFailure(t *testing.T) {
	var failure = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBufferString(``)),
	}
	var failureClient = &http.Client{Transport: &fixtureRoundTripper{failure, nil, nil}}

	var f = NewMultiFetcher(
		NewHTTPKeyFetcher("http://localhost", failureClient),
		NewHTTPKeyFetcher("http://localhost", failureClient),
	)
	_, e := f.Fetch("TEST")
	if e == nil {
		t.Fatalf("MultiFetcher fetcher did fail when all delegate fetchers failed.")
	}
}
