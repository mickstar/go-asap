package asap

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"bitbucket.org/atlassian/go-asap/v2/mocks"
)

const (
	testSecretARN  = "arn:aws:secretsmanager:us-west-2:123456789012:secret:testPrefix" // nolint: gosec
	testKeyID      = "testKeyID"
	testPrivateKey = "testPrivateKey"
)

func TestGetKeyID(t *testing.T) {
	t.Run("Gets the keyID and sets the private key in the map", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(testSecretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s","ASAP_PRIVATE_KEY":"%s"}`, testKeyID, testPrivateKey) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		keyID, err := provider.GetKeyID()

		assert.NoError(t, err)
		assert.Equal(t, "testKeyID", keyID)

		privateKey, exists := provider.privateKeys[keyID]
		assert.True(t, exists)
		assert.Equal(t, "testPrivateKey", privateKey)
	})

	t.Run("Returns an error when failing to get the secret value", func(t *testing.T) {
		mockSecretsManager, provider := buildMockAndProvider(t)

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

func buildMockAndProvider(t *testing.T) (*mocks.SecretsManagerAPI, *SecretsManagerKeypairProvider) {
	mockSecretsManager := mocks.NewSecretsManagerAPI(t)

	provider := &SecretsManagerKeypairProvider{
		client:        mockSecretsManager,
		privateKeyARN: testSecretARN,
		privateKeys:   map[string]string{},
	}

	return mockSecretsManager, provider
}
