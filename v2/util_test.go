package asap

import (
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKeyIDFromToken(t *testing.T) {
	t.Run("Gets the keyID", func(t *testing.T) {
		provisioner := NewProvisioner("testKeyID", time.Hour, "testIssuer", []string{"testAudience"}, crypto.SigningMethodRS256)
		token, err := provisioner.Provision()
		require.NoError(t, err)

		keyID, err := GetKeyIDFromToken(token)

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID", keyID)
	})

	t.Run("Returns an error when failing to get the keyID", func(t *testing.T) {
		provisioner := NewProvisioner("testKeyID", time.Hour, "testIssuer", []string{"testAudience"}, crypto.SigningMethodRS256)
		token, err := provisioner.Provision()
		require.NoError(t, err)
		token.(jws.JWS).Protected().Set(ClaimKeyID, nil)

		_, err = GetKeyIDFromToken(token)

		assert.Error(t, err)
		assert.Equal(t, "Failed to get the keyID from the token", err.Error())
	})
}
