package asap

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"bitbucket.org/atlassian/go-asap/keyprovider"
)

func TestMiddleware(t *testing.T) {
	var lastLogLine string
	lastLineLogger := func(v ...interface{}) {
		switch value := v[0].([]interface{})[0].(type) {
		case error:
			lastLogLine = value.Error()
		case string:
			lastLogLine = value
		}
	}

	log.SetOutput(ioutil.Discard) //Disable output for standard logger

	type authHeader struct {
		Key   string
		Value string
	}

	rsaValidPrivateKeyOne, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Error(err)
	}
	rsaValidPublicKeyOne := rsaValidPrivateKeyOne.Public()

	rsaValidPrivateKeyTwo, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		t.Error(err)
	}
	rsaValidPublicKeyTwo := rsaValidPrivateKeyTwo.Public()

	ecdsaValidPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaValidPublicKey := ecdsaValidPrivateKey.Public()

	if err != nil {
		t.Error(err)
	}

	cases := []struct {
		TestName            string                 // Just for convenience
		PrivateKey          interface{}            // Private key that will be returned by key provider
		PublicKey           crypto.PublicKey       // Public key that will be returned by key provider
		KeyProviderError    error                  // Error that will be returned by keyProvider.GetPublicKey method
		ServerName          string                 // ASAP service ID for server
		ClientName          string                 // ASAP service ID for client
		Logger              func(v ...interface{}) // Logging function for ASAP middleware
		AuthenticationRules []Rule                 // Authentication rules for ASAP middleware
		CustomAuthHeader    authHeader             // Override Authorization header by provided key and value
		ExpectedLastLogLine string                 // Expected log entry.
		ExpectedStatus      int                    // Expected HTTP status code
		ExpectedBody        string                 // Expected HTTP Body
		ExpectedSighError   error                  // Expected asap.Sign error value
	}{
		{
			TestName:   "Happy path",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "",
			ExpectedBody:        "test_body",
			ExpectedStatus:      http.StatusOK,
		},
		{
			TestName:   "Public key is incorrect for the specified private key",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyTwo,
			ServerName: "server",
			ClientName: "client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "crypto/rsa: verification error",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:   "Not allowed client tries to communicate",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "not_allowed_client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "not_allowed_client is not authorized for route /auth/asap",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:   "Should not auth",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "not_allowed_client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile("/the/only/auth/endpoint"), []string{"client"}),
			},
			ExpectedLastLogLine: "",
			ExpectedBody:        "test_body",
			ExpectedStatus:      http.StatusOK,
		},
		{
			TestName:   "No clients specified in auth rules",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), nil),
			},
			ExpectedLastLogLine: "",
			ExpectedBody:        "test_body",
			ExpectedStatus:      http.StatusOK,
		},
		{
			TestName:   "Nil logger",
			PrivateKey: rsaValidPrivateKeyOne,
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "not_allowed_client",
			Logger:     nil,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:         "Missing authorization header",
			PrivateKey:       rsaValidPrivateKeyOne,
			PublicKey:        rsaValidPublicKeyOne,
			CustomAuthHeader: authHeader{Key: "Not specified header", Value: "Doesn't matter"},
			ServerName:       "server",
			ClientName:       "client",
			Logger:           lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "missing authorization header",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:         "Invalid JWT token",
			PrivateKey:       rsaValidPrivateKeyOne,
			PublicKey:        rsaValidPublicKeyOne,
			CustomAuthHeader: authHeader{Key: headerAuthorization, Value: "Invalid JWT"},
			ServerName:       "server",
			ClientName:       "client",
			Logger:           lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "not a compact JWS",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:         "Keyprovider errors are handled correctly",
			PrivateKey:       rsaValidPrivateKeyOne,
			PublicKey:        rsaValidPublicKeyOne,
			KeyProviderError: errors.New("keyprovider error"),
			ServerName:       "server",
			ClientName:       "client",
			Logger:           lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "keyprovider error",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
		},
		{
			TestName:         "Happy path for ECDSA key",
			PrivateKey:       ecdsaValidPrivateKey,
			PublicKey:        ecdsaValidPublicKey,
			KeyProviderError: nil,
			ServerName:       "server",
			ClientName:       "client",
			Logger:           lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "",
			ExpectedBody:        "test_body",
			ExpectedStatus:      http.StatusOK,
		},
		{
			TestName:   "Bad private key provided",
			PrivateKey: "invalidPrivateKey",
			PublicKey:  rsaValidPublicKeyOne,
			ServerName: "server",
			ClientName: "client",
			Logger:     lastLineLogger,
			AuthenticationRules: []Rule{
				NewRule(regexp.MustCompile(".*"), []string{"client"}),
			},
			ExpectedLastLogLine: "not a compact JWS",
			ExpectedBody:        "",
			ExpectedStatus:      http.StatusForbidden,
			ExpectedSighError:   errors.New("bad private key"),
		},
	}

	for _, c := range cases {
		keyProvider := keyprovider.MockKeyProvider{
			Err:        c.KeyProviderError,
			PrivateKey: c.PrivateKey,
			PublicKeys: map[string]interface{}{
				c.ClientName + "/key": c.PublicKey,
			},
		}

		configs := MiddlewareConfigs{
			ASAP: &ASAP{
				ServiceID: c.ServerName,
				KeyID:     c.ServerName + "/key",
			},
			PublicKeyProvider:   keyProvider,
			Logger:              c.Logger,
			AuthenticationRules: c.AuthenticationRules,
		}

		asapMiddleware := NewMiddleware(configs)
		asapClient := NewASAP(c.ClientName+"/key", c.ClientName, []string{})
		token, err := asapClient.Sign(c.ServerName, c.PrivateKey)

		if !reflect.DeepEqual(c.ExpectedSighError, err) {
			t.Logf("Unexpected sign error. Want: %#v, got: %#v", c.ExpectedSighError, err)
			t.Fail()
		}

		nopHandler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test_body"))
		}
		mux := http.NewServeMux()
		mux.Handle("/auth/asap", asapMiddleware(http.HandlerFunc(nopHandler)))

		asapReq, _ := http.NewRequest("GET", "/auth/asap", nil)

		if c.CustomAuthHeader.Key == "" && c.CustomAuthHeader.Value == "" {
			asapReq.Header.Set(headerAuthorization, "Bearer "+string(token))
		} else {
			asapReq.Header.Set(c.CustomAuthHeader.Key, c.CustomAuthHeader.Value)
		}

		rrASAP := httptest.NewRecorder()

		mux.ServeHTTP(rrASAP, asapReq)

		t.Logf("Test: %s", c.TestName)
		if c.ExpectedStatus != rrASAP.Code {
			t.Logf("Unexpected status code. Got: %d, want: %d", rrASAP.Code, c.ExpectedStatus)
			t.Fail()
		}
		if c.ExpectedBody != rrASAP.Body.String() {
			t.Logf("Unexpected response body.\nGot: %s \nWant: %s\n", rrASAP.Body.String(), c.ExpectedBody)
			t.Fail()
		}
		if c.ExpectedLastLogLine != lastLogLine {
			t.Logf("Unexpected last log entry.\nGot: %s \nWant: %s\n", lastLogLine, c.ExpectedLastLogLine)
			t.Fail()
		}
		lastLogLine = "" //reset
	}
}

func TestConfigsValidation(t *testing.T) {
	configs := MiddlewareConfigs{
		Logger: func(v ...interface{}) {},
	}
	configsWithASAP := MiddlewareConfigs{
		Logger: func(v ...interface{}) {},
		ASAP: &ASAP{
			ServiceID: "serviceID",
			KeyID:     "serviceID/key",
		},
	}
	middlewareWithoutASAP := NewMiddleware(configs)
	middlewareWithoutKeyprovider := NewMiddleware(configsWithASAP)

	nopHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test_body"))
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/asap", middlewareWithoutASAP(http.HandlerFunc(nopHandler)))
	mux.Handle("/auth/keyprovider", middlewareWithoutKeyprovider(http.HandlerFunc(nopHandler)))

	withoutASAPRequest, _ := http.NewRequest("GET", "/auth/asap", nil)
	withoutKeyproviderRequest, _ := http.NewRequest("GET", "/auth/keyprovider", nil)

	rr := httptest.NewRecorder()
	rrWithASAP := httptest.NewRecorder()

	mux.ServeHTTP(rr, withoutASAPRequest)
	if rr.Code != http.StatusForbidden {
		t.Log("Incorrect status code")
		t.Fail()
	}
	mux.ServeHTTP(rrWithASAP, withoutKeyproviderRequest)
	if rr.Code != http.StatusForbidden {
		t.Log("Incorrect status code")
		t.Fail()
	}
}

func BenchmarkMiddleware(b *testing.B) {
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 768)
	if err != nil {
		b.Error(err)
	}
	var rsaPublicKey crypto.PublicKey
	rsaPublicKey = rsaPrivateKey.Public()

	keyProvider := keyprovider.MockKeyProvider{
		Err:        nil,
		PrivateKey: rsaPrivateKey,
		PublicKeys: map[string]interface{}{
			"client/key": rsaPublicKey,
		},
	}

	configs := MiddlewareConfigs{
		ASAP: &ASAP{
			ServiceID: "server",
			KeyID:     "server/key",
		},
		PublicKeyProvider: keyProvider,
		Logger:            func(v ...interface{}) {},
		AuthenticationRules: []Rule{
			NewRule(regexp.MustCompile(".*"), []string{"client"}),
		},
	}

	asapMiddleware := NewMiddleware(configs)

	asapClient := NewASAP("client/key", "client", []string{})
	pKey, err := keyProvider.GetPrivateKey()

	if err != nil {
		b.Error(err)
	}

	token, err := asapClient.Sign("server", pKey)

	if err != nil {
		b.Error(err)
	}

	nopHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/asap", asapMiddleware(http.HandlerFunc(nopHandler)))
	mux.HandleFunc("/auth/none", nopHandler)

	asapReq, _ := http.NewRequest("GET", "/auth/asap", nil)
	asapReq.Header.Set(headerAuthorization, "Bearer "+string(token))
	noneAuthRequest, _ := http.NewRequest("GET", "/auth/none", nil)

	rrASAP := httptest.NewRecorder()
	rrNoneAuth := httptest.NewRecorder()

	b.Run("With auth", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mux.ServeHTTP(rrASAP, asapReq)
		}
	})

	b.Run("Without auth", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mux.ServeHTTP(rrNoneAuth, noneAuthRequest)
		}
	})
}
