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
	value, ok := f.cache.Load("TEST")
	if !ok {
		t.Fatalf("Expiring Cache fetcher does not contain a entry under TEST")
	}
	expiringKeyPair, _ := value.(keyExpirationPair)
	if expiringKeyPair.expiration.UTC().Format(http.TimeFormat) != expirationTime.UTC().Format(http.TimeFormat) {
		t.Fatalf("Expiring Cache Fetcher cached %s as expiry date, but expecting %s",
			expiringKeyPair.expiration.UTC().Format(http.TimeFormat), expirationTime.UTC().Format(http.TimeFormat))
	}

	f.cache.Store("NEWKEY", keyExpirationPair{"newkey", expirationTime, 0})
	key, e := f.Fetch("NEWKEY")
	if e != nil {
		t.Fatalf("Expiring Cache fetcher did not parse the response body when item is cached")
	}
	value, ok = f.cache.Load("NEWKEY")
	if !ok {
		t.Fatalf("Expiring Cache fetcher did not contain key NEWKEY")
	}
	expiringKeyPair, _ = value.(keyExpirationPair)
	if key != expiringKeyPair.key {
		t.Fatalf("Expiring Cache fetcher did not use cached value")
	}

}

func TestDefaultCacheControl(t *testing.T) {
	t.Parallel()
	timeNow := func() time.Time {
		return time.Time{}.Add(time.Hour * 3)
	}

	var cacheControlTestTable = []struct {
		in  http.Header
		out string
	}{
		{
			in:  http.Header{"Cache-Control": {"public, max-age=1200"}},
			out: "public, max-age=1200",
		}, {
			in: http.Header{
				"Expires": {timeNow().Add(time.Second * 10).Format(http.TimeFormat)},
			},
			out: "max-age=600",
		},
	}

	for _, tt := range cacheControlTestTable {
		getExpiryAndStaleOk(tt.in, timeNow)
		if ch := tt.in.Get("Cache-Control"); ch != tt.out {
			t.Fatalf("Default Cache-Control was not added")
		}
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
			in:  http.Header{"Cache-Control": {"max-age=lol", "post-check=0", "pre-check=0"}},
			out: timeNow(),
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
			in:  http.Header{"Expires": {"lol"}},
			out: timeNow(),
		}, {
			in:  http.Header{},
			out: timeNow(),
		}, {
			in:    http.Header{"Cache-Control": {"max-age=1200", "stale-while-revalidate=1800"}},
			out:   timeNow().Add(time.Second * 1200),
			stale: 1800 * time.Second,
		}, {
			in:  http.Header{"Cache-Control": {"max-age=1200", "stale-while-revalidate=blah"}},
			out: timeNow(), //NOTE Either header being invalid will flop
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

	value, ok := f.cache.Load("TEST")
	if !ok {
		t.Fatalf("Expiring Cache fetcher does not contain a entry under TEST")
	}
	expiringKeyPair, _ := value.(keyExpirationPair)
	if expiringKeyPair.expiration != timeNow().Add(1200*time.Second) {
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
	calls map[string]float64
}

func (s *mockStats) call(m string, i float64, tags ...string) {
	if s.calls == nil {
		s.calls = map[string]float64{}
	}
	s.calls[m] = s.calls[m] + i
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
		t.Fatalf("Fetch returned error: " + err.Error())
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

	value, ok := f.cache.Load("KEY")
	if !ok {
		t.Fatalf("Cache did not contain key KEY")
	}
	pair, _ := value.(keyExpirationPair)
	if pair.expiration.Format(http.TimeFormat) != newExpiryTime {
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

	value, _ = f.cache.Load("KEY")
	pair, _ = value.(keyExpirationPair)
	if pair.expiration.Format(http.TimeFormat) != newExpiryTime {
		t.Fatalf("Cache refresh goroutine did not run correctly")
	}
	if pair.expiration.Format(http.TimeFormat) != newExpiryTime {
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
		t.Fatalf("Fetch returned error: " + err.Error())
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
		t.Fatalf("Fetch returned error: " + err.Error())
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
		t.Fatalf("Fetch returned error: " + err.Error())
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

	val, ok := f.cache.Load("KEY")
	if !ok {
		t.Fatalf("Cache missing error")
	} else if _, ok := val.(keyLookupMissError); !ok {
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
		t.Fatalf("Fetch returned error: " + err.Error())
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

	if stats.calls["asap.key.cache.lookup_miss"] != 1 {
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
		t.Fatalf("Fetch returned error: " + err.Error())
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
		t.Fatalf("Fetch returned error: " + err.Error())
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
		t.Fatalf("Fetch returned error: " + err.Error())
	}

	response = &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewBufferString("something rather unexpected")),
	}
	transport.SetResponse(response, nil)

	time.Sleep(time.Second)

	_, err = f.Fetch("KEY")
	if err != nil {
		t.Fatalf("Fetch returned error when revalidating: " + err.Error())
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
		t.Fatalf("Fetch returned error: " + err.Error())
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

	if !reflect.DeepEqual(stats.calls, map[string]float64{
		"asap.key.cache.expired": 1,
		"asap.key.cache.hit":     1,
		"asap.key.cache.miss":    1,
	}) {
		t.Fatalf("Unexpected stats response: %+v", stats.calls)
	}
}
