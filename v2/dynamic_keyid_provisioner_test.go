package asap

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvision(t *testing.T) {
	t.Run("Creates a valid token", func(t *testing.T) {
		t.Parallel()
		ttl := time.Hour
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = time.Duration(0) // force a cache refresh
		setUpMockWithValidSecretString(mockSecretsManager, keyIDTwo, privateKeyTwo)
		provisioner := NewDynamicKeyIDProvisioner(ttl, "testIssuer", []string{"testAudience"}, SigningMethodRS256, provider)

		token, err := provisioner.Provision()

		require.NoError(t, err)

		issuer, ok := token.Claims().Issuer()
		require.True(t, ok)
		assert.Equal(t, "testIssuer", issuer)

		JWTID, ok := token.Claims().JWTID()
		require.True(t, ok)
		_, err = uuid.Parse(JWTID)
		assert.NoError(t, err)

		issuedAt, ok := token.Claims().IssuedAt()
		require.True(t, ok)
		assert.IsType(t, time.Time{}, issuedAt)

		expiration, ok := token.Claims().Expiration()
		require.True(t, ok)
		assert.IsType(t, time.Time{}, expiration)

		assert.WithinDuration(t, issuedAt.Add(ttl), expiration, 1*time.Millisecond)

		audience, ok := token.Claims().Audience()
		require.True(t, ok)
		assert.Equal(t, []string{"testAudience"}, audience)

		keyID, ok := token.Protected().Get(ClaimKeyID).(string)
		require.True(t, ok)
		assert.Equal(t, "keyIDTwo", keyID)
	})

	t.Run("Returns an error when failing to get the keyID", func(t *testing.T) {
		t.Parallel()
		ttl := time.Hour
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = time.Duration(0) // force a cache refresh

		input := &secretsmanager.GetSecretValueInput{
			SecretId: new(secretARN),
		}
		mockErr := errors.New("Internal server error")
		mockSecretsManager.On("GetSecretValue", input).Return(nil, mockErr)

		provisioner := NewDynamicKeyIDProvisioner(ttl, "testIssuer", []string{"testAudience"}, SigningMethodRS256, provider)

		_, err := provisioner.Provision()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the secret value")
	})
}
