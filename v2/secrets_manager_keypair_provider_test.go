package asap

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/assert"

	"bitbucket.org/atlassian/go-asap/v2/mocks"
)

func TestGetKeyID(t *testing.T) {
	t.Run("returns the keyID successfully", func(t *testing.T) {
		secretARN := "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-prefix"
		mockSecretsManager := mocks.NewSecretsManagerAPI(t)
		provider := &SecretsManagerKeypairProvider{
			client:        mockSecretsManager,
			privateKeyARN: secretARN,
			privateKeys:   map[string]string{},
		}

		input := &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretARN),
		}
		secretString := `{"ASAP_KEY_ID":"test-keyID","ASAP_PRIVATE_KEY":"private-key"}`
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(secretString),
		}
		mockSecretsManager.On("GetSecretValue", input).Return(output, nil)

		keyID, err := provider.GetKeyID()

		assert.NoError(t, err)
		assert.Equal(t, "test-keyID", keyID)
	})
}
