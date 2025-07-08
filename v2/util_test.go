package asap

import (
	"testing"
	"time"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NonJWS does not implement the jws.JWS interface, simulating a non-JWS token.
type NonJWS struct{}

func (NonJWS) Claims() jwt.Claims { return nil }
func (NonJWS) Validate(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) error {
	return nil
}
func (NonJWS) Serialize(key interface{}) ([]byte, error) { return nil, nil }

// TestJWS is a mock implementation of the jws.JWS interface.
type TestJWS struct {
	header jose.Header
}

func (t TestJWS) Protected() jose.Protected {
	if t.header == nil {
		return nil
	}
	return jose.Protected(t.header)
}
func (TestJWS) Payload() interface{}                                                      { return nil }
func (TestJWS) SetPayload(interface{})                                                    {}
func (TestJWS) ProtectedAt(int) jose.Protected                                            { return nil }
func (TestJWS) Header() jose.Header                                                       { return nil }
func (TestJWS) HeaderAt(int) jose.Header                                                  { return nil }
func (TestJWS) Verify(interface{}, crypto.SigningMethod) error                            { return nil }
func (TestJWS) VerifyMulti([]interface{}, []crypto.SigningMethod, *jws.SigningOpts) error { return nil }
func (TestJWS) VerifyCallback(jws.VerifyCallback, []crypto.SigningMethod, *jws.SigningOpts) error {
	return nil
}
func (TestJWS) General(...interface{}) ([]byte, error) { return nil, nil }
func (TestJWS) Flat(interface{}) ([]byte, error)       { return nil, nil }
func (TestJWS) Compact(interface{}) ([]byte, error)    { return nil, nil }
func (TestJWS) IsJWT() bool                            { return false }

func (TestJWS) Claims() jwt.Claims { return nil }

func (TestJWS) Validate(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) error {
	return nil
}
func (TestJWS) Serialize(key interface{}) ([]byte, error) { return nil, nil }

func TestGetKeyIDFromToken(t *testing.T) {
	t.Run("Gets the keyID", func(t *testing.T) {
		t.Parallel()
		provisioner := NewProvisioner("testKeyID", time.Hour, "iss", []string{"aud"}, crypto.SigningMethodRS256)
		token, err := provisioner.Provision()
		require.NoError(t, err)

		kid, err := GetKeyIDFromToken(token)

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID", kid)
	})

	cases := []struct {
		name   string
		token  Token
		errMsg string
	}{
		{
			"not a JWS",
			NonJWS{},
			"Token is not a JSON web signature",
		},
		{
			"nil header",
			TestJWS{nil},
			"Protected header is nil",
		},
		{
			"missing kid",
			TestJWS{jose.Header{}},
			"Missing the kid header"},
		{
			"non-string kid",
			TestJWS{jose.Header{"kid": 5}},
			"kid header value is not a string",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := GetKeyIDFromToken(c.token)
			assert.EqualError(t, err, c.errMsg)
		})
	}
}
