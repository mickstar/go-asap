package asap

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vincent-petithory/dataurl"
	"golang.org/x/sync/errgroup"
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

const publicKey2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtYr4/AjZHsvizYDxFsUF
S6kvLJS6rbFd7P/l7g8xzg1+T7/OWEGi/oI/RptrR6RP111BrcgpPvroShhcyfis
6ATshf+I2bEVgFGcgWKHTjzO72JdQ9z3VfwQx4THf6kTkXbWUM+9UOyn+yPi+4Rv
Ppj4cC34x1ZKc7LyvP1YDfXlj+nmS7jDtx8idTaSQo7xwzgBjP2bqGQLLvtoAy0S
orAyv2AiSX19YjCSYP/6gqAVAlyyR0cwL0bm5zdlh8zkI6ZZW97kHjZNpUtQxJNY
T7+TCN9nKRjmPqftChTwZvVs9spSUNhP6R6368fOeR2jHB+pljWt7uTVVHvvUBLM
2wIDAQAB
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

// PKCS#8 encoded RSA private key (BEGIN PRIVATE KEY instead of BEGIN RSA PRIVATE KEY)
const privateKeyPKCS8RSA = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDO0rpBdLfkLI5T
Oh1HpFLcZsRDTiVyY6HatvclBGO4GvdSHnjaiavTfJxkTjtMhfUZHLC28T35ifIg
xOSzosNZX8KLdfUxmHJL4SDjr3EZ0Trn1X1X/X3re/HUZzVtW9SqvL3uxGHElM3C
ag1NrplVYwcIIAAHpz1uv5T0/A3bVFJU67JhGW0lJzb+GPXVU+AhnwHvWoZdGeg0
veefUliBmQjl2MxhlkbehHrzqG83lDbJIned0h/CBxJYGghc+joazpwXDzAK7Xm3
6UMFInqkZtoqFzJoF06VwQelC2RYgUGLP6j1F2wwHj3dsb3TFwB4gYtUbbbI2XY+
pOH7OfrXAgMBAAECggEABkdMYy9NY85cdbdWazXYVBuEiryFE39lyvNx9jw3YL/k
0SfeqFe0kSN/xeXAFBce9SezT6JsLLac1JTVkoR25LAtAjnO+zXzBk2rx22sg8mf
vajz+KdX2r20/isx6oN2pcY8B9MLWsHfqy63/6s0uWxbqsn55kGT8lg7h+Jc81MC
fysF+QhMR0epJQFPOux8iyQoiGKbNeYxs5fjfRkt7hclcT52PlHRsBGgJbQ7di5o
zIFJIjhdywznH82AI0OyCqjT3zaKVj8oPMhB6BxhJJTSh+WhJX2Nlo+GEzssSuay
aIbYANvj7283Irt6Y4wbIo9QvTLifXqIz6gmEFzO7QKBgQDwC1T2jdwYrimjQotv
s2EL4DoU7hc2JI42ikDx2RF81xpzgaAohyzrLwZyAnEN2CopJsxCQbq/ypKq1RBS
W4LZ9V/3yw2AmzRgqAq8whNUr0ZFNgJP3yz6ORg8CO3e7ZWLRCe0slwD2utCq+AV
tqsSoJESQNkn/KjggZZxVTziOwKBgQDckhhKtlErma0qIgx/Fvu2QfKCxxVtn16l
BM6HoTzNF0eih8/20AuNf1PNMcM6t4JgIEyasONz25I8DrL9xchF6kIdsnGP8DTS
TFjvV6y+QAVaP8lYxbBZ4V+wrxAixz8uwOq4h3VexN7BCjySCjb0pFjKVVFM7u3U
UIYUc2+EFQKBgQCxrdGgBnVKF3Belh0b+0z0O28CmxG3U+uoV0GnQqN9IsNDiEmC
djw7gT1mGoSQWNcsSrmauYh/+nQB22APdgkvSD9W7Yf7D+b/PKNmAMnKP0rmZAnm
ES37sVNM7NcV0gqFYVd6myMc/2hwm0RtDh8m1I9NUY7r2EswkvtGvG8qjQKBgQCl
KNv5rbTv8d2BTAeRbnNCkPT3Sf1YnVowNH41ft1ZMNJZ+FoXlMbhx/LHFjj6kYiV
U/ooZsWZ7lL8l4EdluiUuYmSVRjFz/atda+uYDcgKi4X2uV4jGa1lpWhZiSt9gXw
i1H2pK+VK9MkNvcN34ow+5Lkxqfe9JWvQjBzxdA91QKBgB8VyZIq1vmm1r9zMY4t
ogX7rpenmQf3k4fS2aVy2JsJ7Zq4annIo14fzCsiFlqOITzhNvIddI3GNq7LDB2u
HORptB1aIp3cpdsLBSFL/kbF1d5evcwM1gFseanocSJcq6RM89+5dn/07ckRq3NT
upEuw+ESrSeScNHS3BshGUU/
-----END PRIVATE KEY-----
`

// PKCS#8 encoded EC private key
const privateKeyPKCS8EC = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjmwWTIEKtF+SsGhc
N4coleNAmvY5UzZjO/B4Q/hXibqhRANCAASoGH4fwv/N1rTu+8TkOKHJzGybIwqH
YQE0xHDtZ71bCk+eNrmqGfMWUzs/lkwhFAy/QlwTHloeNm3RC264pGLw
-----END PRIVATE KEY-----
`

// nolint deadcode
const privateKey2 = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtYr4/AjZHsvizYDxFsUFS6kvLJS6rbFd7P/l7g8xzg1+T7/O
WEGi/oI/RptrR6RP111BrcgpPvroShhcyfis6ATshf+I2bEVgFGcgWKHTjzO72Jd
Q9z3VfwQx4THf6kTkXbWUM+9UOyn+yPi+4RvPpj4cC34x1ZKc7LyvP1YDfXlj+nm
S7jDtx8idTaSQo7xwzgBjP2bqGQLLvtoAy0SorAyv2AiSX19YjCSYP/6gqAVAlyy
R0cwL0bm5zdlh8zkI6ZZW97kHjZNpUtQxJNYT7+TCN9nKRjmPqftChTwZvVs9spS
UNhP6R6368fOeR2jHB+pljWt7uTVVHvvUBLM2wIDAQABAoIBAACiZK5UxZVy9u7q
5WzD8XnLNIv+VQyoUwCyADatvOnQaEGVFP5/9DbZc6kmf+B3NYQ2IjWePm6m58ri
fOiDwu7onX72Xp8MHFwfbOGS25AtbDev602CZybYw6I+14edqqDWfnc30pyGxyt8
e52PX+gjFrMlpfnkVkxDMs/wPq+Fy+zjpNpRX1OJQ00HLrjhOGsK02kxtvpxojak
tWbapAeZuDGThFmdO0IPYGAZgngPCj6kdwfDLSI1W+Vl0jYBoGFlgOIBLxfXbzM4
Ba5FooeLRa11npa1Pg9SOGtR/hrLvQVcMzZ0r3HGnzGehFlgljpyg+aB5OXb2/Qm
PxhyExECgYEA7ouV3eOdJid6a9cdbEysXU3D/2IIgmkEFF10/PM7cMgz4BG2r/bi
dVQNE4a1zOXilX3kSwg52w1s+BUgqexjd3DhdPxA5GtvwDgQUvcoDn6Fqc1/ewFY
D5F2sAjq8Ye9aqyhs7GU1Dzv+6sqld9Xy4DnkYQmbEtw+uDYgOfExKMCgYEAwtOf
OITr8YGR5CBaRBMDyLTmpVwBM+ZgWOJhehV8Yd0Adz0Tutb8bpOT6sHTC3CSrbTd
YWcQzW+NzHAHhQXLXiPOpBXCx8ZO4+SZAfH1AzB4RBUIrBGVf/fHU+BI0mRswVdT
k9PrR7vCVSLBB4f1PC3zg10wVyejA833ABRFomkCgYEAo7eTVOVproz7vVW3MOPy
jFraAMWUl4Rhs2Rs7Uo2anJNACTIID6uL95O1y7mSUkhWH49l61+n7O4LQ+7CkRe
A9SqN/MEyoBeAyu3MGnGySPWsrKCIrbKbGzma2zDap9BxhvTIxPm1D86aZyRLqlJ
hTbkN3/eKwcf9F8q2FW5O0cCgYBsySGUu5PLbF/8E5yTelKYlXpcRv1c73xI5U8s
jia/tll2OyJzJ2wYiksDwGqJbrhYSi97HcOiEnII/10Th+LAlBnkQUpbpn2Sfqh5
D5ORzlS5H02SVtc1dzNTwF6pK+4WHx7J4oDzswGV7CwAeogSrE3WwggmAjnh+/W5
k5g2UQKBgCVsvgcfdOfrMLZ0ACg1rFxRpfrogL0Dc72Qfv1hajzpWFmU6xJQIuS9
E7FtcW57i+GFA1pl0nP1/EkN2okyN+4ArSfiTynKe1RdXrXpheDrcGPlUDIicvUX
igpLGSnt8GFQ9+qttFN4CQ20b/2afPoAlG9dJPf9xeyhLqw0yh8c
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
	t.Parallel()
	var _, e = NewPrivateKey([]byte(privateKey))
	if e != nil {
		t.Fatalf("Could not parse private key %s", e)
	}
}

func TestPrivateKeyParserEncoded(t *testing.T) {
	t.Parallel()
	var data = dataurl.EncodeBytes([]byte(privateKey))
	var _, e = NewPrivateKey([]byte(data))
	if e != nil {
		t.Fatalf("Could not parse private key %s", e)
	}
}

func TestPrivateKeyParserPKCS8RSA(t *testing.T) {
	t.Parallel()
	var _, e = NewPrivateKey([]byte(privateKeyPKCS8RSA))
	if e != nil {
		t.Fatalf("Could not parse PKCS#8 RSA private key %s", e)
	}
}

func TestPrivateKeyParserPKCS8EC(t *testing.T) {
	t.Parallel()
	var _, e = NewPrivateKey([]byte(privateKeyPKCS8EC))
	if e != nil {
		t.Fatalf("Could not parse PKCS#8 EC private key %s", e)
	}
}

func TestPrivateKeyParserPKCS8RSAEncoded(t *testing.T) {
	t.Parallel()
	var data = dataurl.EncodeBytes([]byte(privateKeyPKCS8RSA))
	var _, e = NewPrivateKey([]byte(data))
	if e != nil {
		t.Fatalf("Could not parse encoded PKCS#8 RSA private key %s", e)
	}
}

func TestPrivateKeyParserPKCS8ECEncoded(t *testing.T) {
	t.Parallel()
	var data = dataurl.EncodeBytes([]byte(privateKeyPKCS8EC))
	var _, e = NewPrivateKey([]byte(data))
	if e != nil {
		t.Fatalf("Could not parse encoded PKCS#8 EC private key %s", e)
	}
}

func TestMicrosPrivateKeyParserEncoded(t *testing.T) {
	t.Parallel()
	var data = dataurl.EncodeBytes([]byte(privateKey))
	os.Setenv("ASAP_PRIVATE_KEY", data)
	defer os.Unsetenv("ASAP_PRIVATE_KEY")
	var _, e = NewMicrosPrivateKey()
	if e != nil {
		t.Fatalf("Could not parse private key %s", e)
	}
}

func TestPublicKeyParser(t *testing.T) {
	t.Parallel()
	var _, e = NewPublicKey([]byte(publicKey))
	if e != nil {
		t.Fatalf("Could not parse public key %s", e)
	}
}

func TestHTTPFetcherJoinsKidToPath(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBufferString(``)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	var f = NewHTTPKeyFetcher("http://localhost", client)
	_, _ = f.Fetch("TEST")
	if transport.request.URL.String() != "http://localhost/TEST" {
		t.Fatalf("HTTP fetcher did not use the key id in the path.")
	}
}

func TestHTTPFetcher(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestExpiringHTTPFetcherJoinsKidToPath(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       ioutil.NopCloser(bytes.NewBufferString(``)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	f, err := NewExpiringCacheFetcher("http://localhost", client, 0)
	if err != nil {
		t.Fatalf("Failed to initialize fetcher")
	}
	_, _ = f.Fetch("TEST")
	if transport.request.URL.String() != "http://localhost/TEST" {
		t.Fatalf("HTTP fetcher did not use the key id in the path.")
	}
}

func TestExpiringHTTPFetcherFetch(t *testing.T) {
	t.Parallel()
	var expirationTime = time.Now().AddDate(0, 0, 2)
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Expires": {expirationTime.UTC().Format(http.TimeFormat)}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	var fetcher, e = NewExpiringCacheFetcher("http://localhost", client, 3000)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}

	var f = fetcher.(*expiringCacheFetcher)
	_, e = f.Fetch("TEST")
	if e != nil {
		t.Fatalf("Expiring Cache fetcher did not parse the response body.")
	}
	f.cache.Wait()
	value, ok := f.cache.Get("TEST")
	if !ok {
		t.Fatalf("Expiring Cache fetcher does not contain a entry under TEST")
	}
	expiringKeyPair := value
	if expiringKeyPair.freshUntil.UTC().Format(http.TimeFormat) != expirationTime.UTC().Format(http.TimeFormat) {
		t.Fatalf("Expiring Cache Fetcher cached %s as expiry date, but expecting %s",
			expiringKeyPair.freshUntil.UTC().Format(http.TimeFormat), expirationTime.UTC().Format(http.TimeFormat))
	}

	f.storeKey("NEWKEY", keyExpirationPair{"newkey", expirationTime, 0})
	f.cache.Wait()
	key, e := f.Fetch("NEWKEY")
	if e != nil {
		t.Fatalf("Expiring Cache fetcher did not parse the response body when item is cached")
	}
	value, ok = f.cache.Get("NEWKEY")
	if !ok {
		t.Fatalf("Expiring Cache fetcher did not contain key NEWKEY")
	}
	expiringKeyPair = value
	if key != expiringKeyPair.key {
		t.Fatalf("Expiring Cache fetcher did not use cached value")
	}

}

func TestGetExpiryDate(t *testing.T) {
	t.Parallel()
	timeNow := func() time.Time {
		return time.Time{}.Add(time.Hour * 3)
	}

	var expiryTestTable = []struct {
		in    http.Header
		out   time.Time
		stale time.Duration
	}{
		{
			in:  http.Header{"Cache-Control": {"public, max-age=1200"}},
			out: timeNow().Add(time.Second * 1200),
		}, {
			in:  http.Header{"Cache-Control": {"max-age=1200", "post-check=0", "pre-check=0"}},
			out: timeNow().Add(time.Second * 1200),
		}, {
			in:    http.Header{"Cache-Control": {"max-age=lol", "post-check=0", "pre-check=0"}},
			out:   timeNow().Add(time.Minute * 10),
			stale: time.Duration(time.Minute * 20),
		}, {
			in: http.Header{
				"Cache-Control": {"max-age=lol", "post-check=0", "pre-check=0"},
				"Expires":       {timeNow().Add(time.Second * 10).Format(http.TimeFormat)},
			},
			out: timeNow().Add(time.Second * 10),
		}, {
			in:  http.Header{"Expires": {timeNow().Add(time.Second * 10).Format(http.TimeFormat)}},
			out: timeNow().Add(time.Second * 10),
		}, {
			in:    http.Header{"Expires": {"lol"}},
			out:   timeNow().Add(time.Minute * 10),
			stale: time.Duration(time.Minute * 20),
		}, {
			in:    http.Header{},
			out:   timeNow().Add(time.Minute * 10),
			stale: time.Duration(time.Minute * 20),
		}, {
			in:    http.Header{"Cache-Control": {"max-age=1200", "stale-while-revalidate=1800"}},
			out:   timeNow().Add(time.Second * 1200),
			stale: 1800 * time.Second,
		}, {
			in:    http.Header{"Cache-Control": {"max-age=1200", "stale-while-revalidate=blah"}},
			out:   timeNow().Add(time.Minute * 10), //NOTE Either header being invalid will flop
			stale: time.Duration(time.Minute * 20),
		}}

	for _, tt := range expiryTestTable {
		expiryTime, staleOk := getExpiryAndStaleOk(tt.in, timeNow)
		if expiryTime != tt.out {
			t.Fatalf("expiry time of %s returned %s instead of the expected %s",
				tt.in, expiryTime.String(), tt.out.String())
		} else if staleOk != tt.stale {
			t.Fatalf("stale of %s returned %s instead of the expected %s",
				tt.in, staleOk.String(), tt.stale.String())
		}
	}
}

func TestExpiringHTTPFetcherCache(t *testing.T) {
	t.Parallel()
	timeNow := func() time.Time {
		return time.Time{}.Add(time.Hour * 3)
	}
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1200"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &fixtureRoundTripper{response, nil, nil}
	var client = &http.Client{Transport: transport}

	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, 3000)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}

	f := fetcher.(*expiringCacheFetcher)
	f.timeNow = timeNow
	_, e = f.Fetch("TEST")
	if e != nil {
		t.Fatalf("Expiring Cache fetcher did not parse the response body.")
	}
	f.cache.Wait()

	value, ok := f.cache.Get("TEST")
	if !ok {
		t.Fatalf("Expiring Cache fetcher does not contain a entry under TEST")
	}
	expiringKeyPair := value
	if expiringKeyPair.freshUntil != timeNow().Add(1200*time.Second) {
		t.Fatalf("Expiring Cache Fetcher does not return correct expiry time from Cache-Control header")
	}
}

type lockingFixtureRoundTripper struct {
	response *http.Response
	e        error
	request  *http.Request
	lock     *sync.Mutex
	sleep    time.Duration
}

func (r *lockingFixtureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	time.Sleep(r.sleep)
	r.request = req
	return r.response, r.e
}

func (r *lockingFixtureRoundTripper) SetResponse(res *http.Response, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.response = res
	r.e = err
	r.sleep = 0
}

func (r *lockingFixtureRoundTripper) SetDelayedResponse(res *http.Response, delay time.Duration, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.response = res
	r.e = err
	r.sleep = delay
}

func (r *lockingFixtureRoundTripper) GetRequest() *http.Request {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.request
}

type mockStats struct {
	mu    sync.Mutex
	calls map[string]float64
}

func (s *mockStats) call(m string, i float64, tags ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]float64{}
	}
	s.calls[m] = s.calls[m] + i
}

func (s *mockStats) getCalls() map[string]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]float64)
	for k, v := range s.calls {
		result[k] = v
	}
	return result
}

func (s *mockStats) getCall(key string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[key]
}

func TestExpiringHTTPFetcherCacheRefresh(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Expires": {time.Now().UTC().Add(time.Second).Format(http.TimeFormat)}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	// Test initial re-fetch
	newExpiryTime := time.Now().UTC().Add(time.Second).Format(http.TimeFormat)
	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Expires": {newExpiryTime}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Millisecond)

	value, ok := f.cache.Get("KEY")
	if !ok {
		t.Fatalf("Cache did not contain key KEY")
	}
	pair := value
	if pair.freshUntil.Format(http.TimeFormat) != newExpiryTime {
		t.Fatalf("Cache refresh goroutine did not run correctly")
	}

	// Test second spawned re-fetch goroutine
	newExpiryTime = time.Now().UTC().Add(time.Second).Format(http.TimeFormat)
	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Expires": {newExpiryTime}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Millisecond)

	value, _ = f.cache.Get("KEY")
	pair = value
	if pair.freshUntil.Format(http.TimeFormat) != newExpiryTime {
		t.Fatalf("Cache refresh goroutine did not run correctly")
	}
	if pair.freshUntil.Format(http.TimeFormat) != newExpiryTime {
		t.Fatalf("Cache refresh goroutine did not run correctly")
	}
}

func TestExpiringHTTPFetcherCacheStaleRefresh(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	// Test initial re-fetch
	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey2)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value %+v != %+v", value, pk)
	}

	time.Sleep(time.Millisecond)

	value, err = f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}

	pk, _ = NewPublicKey([]byte(publicKey2))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}
}

func TestExpiringHTTPFetcherCacheStaleRefreshSlowResponse(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	// Test initial re-fetch
	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey2)),
	}
	transport.SetDelayedResponse(response, time.Second, nil)

	time.Sleep(time.Second)

	var eg errgroup.Group
	eg.Go(func() error {
		value, err := f.Fetch("KEY")
		if err != nil {
			return fmt.Errorf("Cache did not contain key KEY %s", err)
		}
		pk, _ := NewPublicKey([]byte(publicKey))
		if !reflect.DeepEqual(value, pk) {
			return fmt.Errorf("Cache didn't return cached value %+v != %+v", value, pk)
		}
		return nil
	})

	time.Sleep(10 * time.Millisecond)

	eg.Go(func() error {
		value, err := f.Fetch("KEY")
		if err != nil {
			return fmt.Errorf("Cache did not contain key KEY %s", err)
		}

		pk, _ := NewPublicKey([]byte(publicKey))
		if !reflect.DeepEqual(value, pk) {
			return fmt.Errorf("Cache didn't return cached value")
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestExpiringHTTPFetcherCacheStalePurge(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}

	time.Sleep(time.Millisecond)

	val, ok := f.cache.Get("KEY")
	if !ok {
		t.Fatalf("Cache missing error")
	} else if !val.isMiss {
		t.Fatalf("Cache missing key lookup error")
	}
}

func TestExpiringHTTPFetcherCacheStalePurgeSlowResponse(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetDelayedResponse(response, time.Second, nil)

	time.Sleep(time.Second)

	var eg errgroup.Group
	eg.Go(func() error {
		value, err := f.Fetch("KEY")
		if err != nil {
			return fmt.Errorf("Cache did not contain key KEY %s", err)
		}
		pk, _ := NewPublicKey([]byte(publicKey))
		if !reflect.DeepEqual(value, pk) {
			return fmt.Errorf("Cache didn't return cached value")
		}
		return nil
	})

	time.Sleep(10 * time.Millisecond)

	eg.Go(func() error {
		value, err := f.Fetch("KEY")
		if err != nil {
			return fmt.Errorf("Cache did not contain key KEY %s", err)
		}
		pk, _ := NewPublicKey([]byte(publicKey))
		if !reflect.DeepEqual(value, pk) {
			return fmt.Errorf("Cache didn't return cached value")
		}
		return nil
	})

	time.Sleep(1 * time.Second)

	eg.Go(func() error {
		_, err := f.Fetch("KEY")
		if err == nil {
			return fmt.Errorf("Fetch returned success")
		} else if _, ok := err.(keyLookupMissError); !ok {
			return fmt.Errorf("Cache missing key lookup error")
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestExpiringHTTPFetcherTemporaryNegativeCache(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var stats = &mockStats{}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcherWithStats("http://localhost", client, stats.call)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err == nil {
		t.Fatalf("Fetch returned non error")
	}
	f.cache.Wait()

	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetResponse(response, nil)

	_, err = f.Fetch("KEY")
	if err == nil {
		t.Fatalf("Fetch not negative caching")
	}

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}

	if stats.getCall("asap.key.cache.lookup_miss") != 1 {
		t.Fatalf("Stats not recorded correctly")
	}
}

func TestExpiringHTTPFetcherKeepOnNetworkError(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}

	time.Sleep(time.Millisecond)
}

func TestExpiringHTTPFetcherKeepOnTimeoutError(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport, Timeout: 1 * time.Second}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	transport.SetDelayedResponse(response, 2*time.Second, nil)

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}

	time.Sleep(time.Second)

	value, err = f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ = NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}
}

func TestExpiringHTTPFetcherDropOnBadResponse(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}
	fetcher, e := NewExpiringCacheFetcher("http://localhost", client, time.Second)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	f := fetcher.(*expiringCacheFetcher)
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBufferString("something rather unexpected")),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	_, err = f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error when revalidating: %s", err.Error())
	}

	time.Sleep(time.Second)
	_, err = f.Fetch("KEY")
	if err == nil {
		t.Fatalf("Cache did not return error")
	}
}

func TestExpiringHTTPFetcherCacheStaleRefreshWithStats(t *testing.T) {
	t.Parallel()
	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	stats := &mockStats{}
	var client = &http.Client{Transport: transport}
	f, e := NewExpiringCacheFetcherWithStats("http://localhost", client, stats.call)
	if e != nil {
		t.Fatalf("Expiring Cache fetcher constructor did not succeed.")
	}
	_, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error: %s", err.Error())
	}

	// Test initial re-fetch
	response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey2)),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	value, err := f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}
	pk, _ := NewPublicKey([]byte(publicKey))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value %+v != %+v", value, pk)
	}

	time.Sleep(5 * time.Millisecond)

	value, err = f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Cache did not contain key KEY %s", err)
	}

	pk, _ = NewPublicKey([]byte(publicKey2))
	if !reflect.DeepEqual(value, pk) {
		t.Fatalf("Cache didn't return cached value")
	}

	if !reflect.DeepEqual(stats.getCalls(), map[string]float64{
		"asap.key.cache.expired":              1,
		"asap.key.cache.hit":                  1,
		"asap.key.cache.miss":                 1,
		"asap.key.cache.refresh.force_reload": 2,
	}) {
		t.Fatalf("Unexpected stats response: %+v", stats.getCalls())
	}
}

func TestKeyCacheSizeLimit(t *testing.T) {
	t.Parallel()

	var response = &http.Response{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Cache-Control": {"max-age=1", "stale-while-revalidate=10"}},
		Body:       ioutil.NopCloser(bytes.NewBufferString(publicKey)),
	}
	var transport = &lockingFixtureRoundTripper{response, nil, nil, &sync.Mutex{}, 0}
	var client = &http.Client{Transport: transport}

	fetcher, _ := NewExpiringCacheFetcher("http://localhost", client, time.Duration(2*time.Minute))
	cacheImpl := fetcher.(*expiringCacheFetcher).WithMaxCacheSize(2)

	expiration := time.Now().Add(time.Minute)
	cacheImpl.storeKey("key", keyExpirationPair{"key", expiration, time.Minute})
	cacheImpl.storeKey("key2", keyExpirationPair{"key2", expiration, time.Minute})
	cacheImpl.storeKey("key3", keyExpirationPair{"key3", expiration, time.Minute})
	cacheImpl.cache.Wait()

	var cached int
	for _, key := range []string{"key", "key2", "key3"} {
		if _, ok := cacheImpl.cache.Get(key); ok {
			cached++
		}
	}
	require.LessOrEqual(t, cached, 2)
}
