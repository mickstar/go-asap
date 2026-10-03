package asap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubToken is a minimal Token implementation for header edge cases.
type stubToken struct {
	header Header
	claims Claims
}

func (t stubToken) Claims() Claims              { return t.claims }
func (t stubToken) Protected() Header           { return t.header }
func (stubToken) Serialize(any) ([]byte, error) { return nil, nil }
func (stubToken) Validate(any, SigningMethod, ...*ValidationOptions) error {
	return nil
}

func TestGetKeyIDFromToken(t *testing.T) {
	t.Run("Gets the keyID", func(t *testing.T) {
		t.Parallel()
		provisioner := NewProvisioner("testKeyID", time.Hour, "iss", []string{"aud"}, SigningMethodRS256)
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
			"nil header",
			stubToken{header: nil},
			"Protected header is nil",
		},
		{
			"missing kid",
			stubToken{header: Header{}},
			"Missing the kid header",
		},
		{
			"non-string kid",
			stubToken{header: Header{"kid": 5}},
			"kid header value is not a string",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := GetKeyIDFromToken(c.token)
			assert.EqualError(t, err, c.errMsg)
		})
	}
}
