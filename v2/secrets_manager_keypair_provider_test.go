package asap

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"bitbucket.org/atlassian/go-asap/v2/mocks"
)

const (
	testSecretARN   = "arn:aws:secretsmanager:us-west-2:123456789012:secret:testPrefix" // nolint: gosec
	testKeyID       = "testKeyID"
	testKeyID2      = "testKeyID2"
	testPrivateKey  = "testPrivateKey"
	testPrivateKey2 = "testPrivateKey2"
)

func TestGetKeyID(t *testing.T) {
	t.Run("Gets the keyID and updates the variables (with cache refresh)", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		originalLastUpdatedTime := provider.lastUpdatedTime
		provider.cacheTTL = 0 // force a cache refresh

		setUpMockWithValidSecretString(mockSecretsManager, testKeyID, testPrivateKey)

		keyID, err := provider.GetKeyID()

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "testPrivateKey", privateKey)
		assert.Equal(t, "testKeyID", provider.latestKeyID)
		assert.Greater(t, provider.lastUpdatedTime.UnixNano(), originalLastUpdatedTime.UnixNano())
	})

	t.Run("Gets the keyID (without cache refresh)", func(t *testing.T) {
		_, provider := buildMockAndProvider(t)

		keyID, err := provider.GetKeyID()

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "testPrivateKey", privateKey)
		assert.Equal(t, "testKeyID", provider.latestKeyID)
	})

	t.Run("Gets the keyID and updates the variables after the secret value changes (with cache refresh)", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		originalLastUpdatedTime := provider.lastUpdatedTime
		provider.cacheTTL = 0 // force a cache refresh

		setUpMockWithValidSecretString(mockSecretsManager, testKeyID2, testPrivateKey2)

		keyID, err := provider.GetKeyID()

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID2", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "testPrivateKey2", privateKey)
		assert.Equal(t, "testKeyID2", provider.latestKeyID)
		assert.Greater(t, provider.lastUpdatedTime.UnixNano(), originalLastUpdatedTime.UnixNano())
	})

	t.Run("Returns an error when failing to get the secret value", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = 0 // force a cache refresh

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(testSecretARN),
		}
		mockErr := errors.New("Internal server error")
		mockSecretsManager.On("GetSecretValue", input).Return(nil, mockErr)

		_, err := provider.GetKeyID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the secret value")
	})

	t.Run("Returns an error when failing to get the keyID from the secret value", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = 0 // force a cache refresh

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(testSecretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_PRIVATE_KEY":"%s"}`, testPrivateKey) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		_, err := provider.GetKeyID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the keyID from the secret value")
	})

	t.Run("Returns an error when failing to get the private key from the secret value", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = 0 // force a cache refresh

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(testSecretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, testKeyID) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		_, err := provider.GetKeyID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the private key from the secret value")
	})
}

func TestFetch(t *testing.T) {
	t.Run("Gets the private key", func(t *testing.T) {
		_, provider := buildMockAndProvider(t)

		keyID, err := provider.GetKeyID()
		require.NoError(t, err)
		privateKey, err := provider.Fetch(keyID)

		assert.NoError(t, err)
		assert.Equal(t, "testPrivateKey", privateKey)
	})

	t.Run("Returns an error when failing to get the private key", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)
		provider.cacheTTL = 0 // force a cache refresh

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(testSecretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, testKeyID2) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		_, err := provider.GetKeyID()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the private key from the secret value")
		_, err = provider.Fetch(testKeyID2)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the private key from the map")
	})
}

func buildMockAndProvider(t *testing.T) (*mocks.SecretsManagerAPI, *SecretsManagerKeypairProvider) {
	mockSecretsManager := mocks.NewSecretsManagerAPI(t)

	provider := &SecretsManagerKeypairProvider{
		client:          mockSecretsManager,
		privateKeyARN:   testSecretARN,
		cacheTTL:        defaultCacheTTL,
		privateKeys:     map[string]string{},
		lastUpdatedTime: time.Now(),
	}

	provider.cacheTTL = time.Duration(0) // force a cache refresh

	setUpMockWithValidSecretString(mockSecretsManager, testKeyID, testPrivateKey)

	keyID, err := provider.GetKeyID()
	require.NoError(t, err)

	provider.latestKeyID = keyID
	provider.cacheTTL = defaultCacheTTL

	return mockSecretsManager, provider
}

func setUpMockWithValidSecretString(mockSecretsManager *mocks.SecretsManagerAPI, keyID, privateKey string) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(testSecretARN),
	}
	secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s","ASAP_PRIVATE_KEY":"%s"}`, keyID, privateKey) // nolint: gosec
	output := &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(secretString),
	}
	mockSecretsManager.On("GetSecretValue", input).Return(output, nil).Once()
}
