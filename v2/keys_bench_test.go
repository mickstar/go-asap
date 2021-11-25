package asap

import (
	"net/http"
	"testing"
	"time"
)

// goos: darwin
// goarch: amd64
// pkg: bitbucket.org/atlassian/go-asap
// BenchmarkGetExpiryTimeClassic
// BenchmarkGetExpiryTimeClassic-8   	 2441078	       494 ns/op	      32 B/op	       1 allocs/op
// BenchmarkGetExpiryTimeLib
// BenchmarkGetExpiryTimeLib-8       	 3190723	       371 ns/op	      80 B/op	       1 allocs/op

var headers = http.Header{
	"Cache-Control": {"max-age=600, stale-while-revalidate=600"},
}

// func BenchmarkGetExpiryTimeClassic(b *testing.B) {
// 	for i := 0; i < b.N; i++ {
// 		getExpiryTime(headers, maxAgeCompiled, time.Now)
// 	}
// }

func BenchmarkGetExpiryTimeLib(b *testing.B) {
	for i := 0; i < b.N; i++ {
		getExpiryAndStaleOk(headers, time.Now)
	}
}
