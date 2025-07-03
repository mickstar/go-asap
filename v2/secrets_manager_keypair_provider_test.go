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
	secretARN     = "arn:aws:secretsmanager:us-west-2:123456789012:secret:testPrefix" // nolint: gosec
	keyIDOne      = "keyIDOne"
	keyIDTwo      = "keyIDTwo"
	privateKeyOne = "privateKeyOne"
	privateKeyTwo = "privateKeyTwo"
)

func TestGetKeyID(t *testing.T) {
	t.Run("Refresh the cache when the latestKeyID has not been set", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		setUpMockWithValidSecretString(mockSecretsManager, keyIDOne, privateKeyOne)

		// this is the first time GetKeyID is called, so it will refresh the cache
		keyID, err := provider.GetKeyID()
		require.NoError(t, err)
		assert.Equal(t, "keyIDOne", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "privateKeyOne", privateKey)
		assert.Equal(t, "keyIDOne", provider.latestKeyID)
	})

	t.Run("Refresh the cache when the keyID exists and it is time to refresh", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		setUpMockWithValidSecretString(mockSecretsManager, keyIDOne, privateKeyOne)
		setUpMockWithValidSecretString(mockSecretsManager, keyIDTwo, privateKeyTwo)

		// make the first call to GetKeyID, which will set the latestKeyID
		_, err := provider.GetKeyID()
		require.NoError(t, err)

		// set the cacheTTL to 0 to force a refresh
		provider.cacheTTL = time.Duration(0)

		// make the second call to GetKeyID, which should refresh because the cacheTTL was set to 0
		keyID, err := provider.GetKeyID()
		require.NoError(t, err)
		assert.Equal(t, "keyIDTwo", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "privateKeyTwo", privateKey)
		assert.Equal(t, "keyIDTwo", provider.latestKeyID)
	})

	t.Run("Get the latestKeyID when the keyID exists and it is not time to refresh", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		setUpMockWithValidSecretString(mockSecretsManager, keyIDOne, privateKeyOne)

		// make the first call to GetKeyID, which will set the latestKeyID
		_, err := provider.GetKeyID()
		require.NoError(t, err)

		// don't set the cacheTTL to 0, so that the cache won't refresh

		// make the second call to GetKeyID, which should get the latestKeyID because the cache won't refresh
		keyID, err := provider.GetKeyID()
		require.NoError(t, err)
		assert.Equal(t, "keyIDOne", keyID)

		privateKey, exists := provider.privateKeys[provider.latestKeyID]
		assert.True(t, exists)
		assert.Equal(t, "privateKeyOne", privateKey)
		assert.Equal(t, "keyIDOne", provider.latestKeyID)
	})

	t.Run("Returns an error when failing to get the secret value", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretARN),
		}
		mockErr := errors.New("Internal server error")
		mockSecretsManager.On("GetSecretValue", input).Return(nil, mockErr)

		_, err := provider.GetKeyID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the secret value")
	})

	t.Run("Returns an error when failing to get the keyID from the secret value", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_PRIVATE_KEY":"%s"}`, privateKeyOne) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		_, err := provider.GetKeyID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the keyID from the secret value")
	})

	t.Run("Returns an error when failing to get the private key from the secret value", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, keyIDOne) // nolint: gosec
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
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		setUpMockWithValidSecretString(mockSecretsManager, keyIDOne, privateKeyOne)

		keyID, err := provider.GetKeyID()
		require.NoError(t, err)
		privateKey, err := provider.Fetch(keyID)

		assert.NoError(t, err)
		assert.Equal(t, "privateKeyOne", privateKey)
	})

	t.Run("Returns an error when failing to get the private key", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, keyIDTwo) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		_, err := provider.GetKeyID()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the private key from the secret value")
		_, err = provider.Fetch(keyIDTwo)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to get the private key from the map")
	})
}

func buildMockAndProvider(t *testing.T) (*mocks.SecretsManagerAPI, *SecretsManagerKeypairProvider) {
	mockSecretsManager := mocks.NewSecretsManagerAPI(t)

	provider := &SecretsManagerKeypairProvider{
		client:          mockSecretsManager,
		privateKeyARN:   secretARN,
		cacheTTL:        defaultCacheTTL,
		latestKeyID:     "",
		privateKeys:     map[string]string{},
		lastUpdatedTime: time.Time{},
	}

	return mockSecretsManager, provider
}

func setUpMockWithValidSecretString(mockSecretsManager *mocks.SecretsManagerAPI, keyID, privateKey string) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretARN),
	}
	secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s","ASAP_PRIVATE_KEY":"%s"}`, keyID, privateKey) // nolint: gosec
	output := &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(secretString),
	}
	mockSecretsManager.On("GetSecretValue", input).Return(output, nil).Once()
}
