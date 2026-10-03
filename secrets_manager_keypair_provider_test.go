package asap

import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mickstar/go-asap/mocks"
)

const (
	secretARN     = "arn:aws:secretsmanager:us-west-2:123456789012:secret:testPrefix" // nolint: gosec
	keyIDOne      = "keyIDOne"
	keyIDTwo      = "keyIDTwo"
	privateKeyOne = "data:application/pkcs8;kid=keyIDOne;base64,MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLUDAHZOHHOocBORGT6dm4nec69G9hsryM1Et/U71rRyrbg3pEQrO2UNmLi3RFIBMW7K/i/M7dDmJENRlsTBJU/d9NcTNAsMotvgMXnlpgQS/1/GTeG2hWPoKCXJmsDLpvrk3KJmBGtzt5IGJsErQ6JjrmV6R6KgtSSP4E+xbjhcCabTBJfbOKtiizcimSlMYkvuuZkA6FCt1/uRMGtvTpUxmchXdVn/LTKUiNaESpQbKp5Wez7+4opaGRyBxe4uPOLdu8D0bYDAmDt6h/Mryqme9fEzfZPv1wr+toj4SOzCgsreGtV2iKYdQNh4wnpS0uDNgVL8BqqAuEidfBClBDAgMBAAECggEAT6KbDWpgXS75jmsSDYO9eeivl5ICxpvB6s+EutzMBucbTFwVWgNebP0CGPyIkELd907CHgCz7jYiG2FJEfhB/fRqsOS0FJSqvHv+rhOihq1B4fH4eF734UAe0nz+3DsoE3KMma+qakh/DRS4OGijG1u6Glsd25P4V0Sr6ruG3Zrk1MVvCCQdGyrke2ogWcnapGIE9wa5U+C5r10mDZHgCNrH5qYPNkZMYHk4NMob3vSrmuweekKjo61K/F2CuhfF9L08bT3c8Fcwz1S114XWDMqlI65d4DGm05/6lqzy38OoeqvOfQULr+rqfFlgLpVAfHtTTGz1J2dASLU7evvUYQKBgQDRfpyVh+3OdLuATlDostXj1xCqkHsjzJx+MfBAgmFcJbAYIlVpNp8LglYTppnbmBeNACBMrEhnSDA45jWuDnlBZUYB7Y0CKxSGlum3pp+O/P85IOrTIn8AzhLfjC3ZdeUylf+ja5zojWqE25H3Th27LIryCUaLLTHUmWU74tzQywKBgQD4cku1ugLjUWBxZv+q56l1Ua7g/Naajbo1k7mR4u+4IZJdHMiUWcml7ULk+uNi7uSXed0bIDdQj+jYuirIjSQ+YNDcrI8NL3Lh8KOGaij5HZdXf6THGWeofhXVe6aQgLuipu7vSNBVS5XFo32BJN5lmjtQVp/F4YdzVW/ryYVnaQKBgHgwOmdzX5SF1hirVbHa/+lCNpaUY4FLXzDrN5na8z5phNijwfql0qNIuFd3ymd4n3JOczlp0fQnLztFn+Bm/1vsXTi376Eh1BnPNPEfEAV50ncVEoPlE5YDpEJKaveKst7NvaclExU8JLNqQRjv4RDEYkav2Z/5YtBE3RZ5dhP3AoGAZsS4hopUCX2u3BnT5fj/wrSwFwbfKn03qlPZ7fumV08jwPpYCe1+GPGkux0Ak/rnebUB/ed8mgl9MrEHY3/mnxrjKnUCk1yuM8Gbks00958C7EGzglwC4dKN64nDY4CsnOJacYZ4DuA+Ksuu7Y23pOWAZYH/gxYANnf/3NO2KAkCgYEAw3xB5L+Wzfl3NnX411iV2d9nK+R7fp5m9rA5wDNiUJTq1J3J8iidh98kHhYpib+IOOAdTTD25mod93637EoTQEyqEJ3B1a+h26Si0Qtbhe+WfQWWK4/tGsYA/wW3h5N2Ufr90f7IZKhFWqZZeKCxx0IIlvIxwoDPziR6n5r5JDo="
	privateKeyTwo = "data:application/pkcs8;kid=keyIDTwo;base64,MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLUDAHZOHHOocBORGT6dm4nec69G9hsryM1Et/U71rRyrbg3pEQrO2UNmLi3RFIBMW7K/i/M7dDmJENRlsTBJU/d9NcTNAsMotvgMXnlpgQS/1/GTeG2hWPoKCXJmsDLpvrk3KJmBGtzt5IGJsErQ6JjrmV6R6KgtSSP4E+xbjhcCabTBJfbOKtiizcimSlMYkvuuZkA6FCt1/uRMGtvTpUxmchXdVn/LTKUiNaESpQbKp5Wez7+4opaGRyBxe4uPOLdu8D0bYDAmDt6h/Mryqme9fEzfZPv1wr+toj4SOzCgsreGtV2iKYdQNh4wnpS0uDNgVL8BqqAuEidfBClBDAgMBAAECggEAT6KbDWpgXS75jmsSDYO9eeivl5ICxpvB6s+EutzMBucbTFwVWgNebP0CGPyIkELd907CHgCz7jYiG2FJEfhB/fRqsOS0FJSqvHv+rhOihq1B4fH4eF734UAe0nz+3DsoE3KMma+qakh/DRS4OGijG1u6Glsd25P4V0Sr6ruG3Zrk1MVvCCQdGyrke2ogWcnapGIE9wa5U+C5r10mDZHgCNrH5qYPNkZMYHk4NMob3vSrmuweekKjo61K/F2CuhfF9L08bT3c8Fcwz1S114XWDMqlI65d4DGm05/6lqzy38OoeqvOfQULr+rqfFlgLpVAfHtTTGz1J2dASLU7evvUYQKBgQDRfpyVh+3OdLuATlDostXj1xCqkHsjzJx+MfBAgmFcJbAYIlVpNp8LglYTppnbmBeNACBMrEhnSDA45jWuDnlBZUYB7Y0CKxSGlum3pp+O/P85IOrTIn8AzhLfjC3ZdeUylf+ja5zojWqE25H3Th27LIryCUaLLTHUmWU74tzQywKBgQD4cku1ugLjUWBxZv+q56l1Ua7g/Naajbo1k7mR4u+4IZJdHMiUWcml7ULk+uNi7uSXed0bIDdQj+jYuirIjSQ+YNDcrI8NL3Lh8KOGaij5HZdXf6THGWeofhXVe6aQgLuipu7vSNBVS5XFo32BJN5lmjtQVp/F4YdzVW/ryYVnaQKBgHgwOmdzX5SF1hirVbHa/+lCNpaUY4FLXzDrN5na8z5phNijwfql0qNIuFd3ymd4n3JOczlp0fQnLztFn+Bm/1vsXTi376Eh1BnPNPEfEAV50ncVEoPlE5YDpEJKaveKst7NvaclExU8JLNqQRjv4RDEYkav2Z/5YtBE3RZ5dhP3AoGAZsS4hopUCX2u3BnT5fj/wrSwFwbfKn03qlPZ7fumV08jwPpYCe1+GPGkux0Ak/rnebUB/ed8mgl9MrEHY3/mnxrjKnUCk1yuM8Gbks00958C7EGzglwC4dKN64nDY4CsnOJacYZ4DuA+Ksuu7Y23pOWAZYH/gxYANnf/3NO2KAkCgYEAw3xB5L+Wzfl3NnX411iV2d9nK+R7fp5m9rA5wDNiUJTq1J3J8iidh98kHhYpib+IOOAdTTD25mod93637EoTQEyqEJ3B1a+h26Si0Qtbhe+WfQWWK4/tGsYA/wW3h5N2Ufr90f7IZKhFWqZZeKCxx0IIlvIxwoDPziR6n5r5JDo="
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
		assert.IsType(t, &rsa.PrivateKey{}, privateKey)
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
		assert.IsType(t, &rsa.PrivateKey{}, privateKey)
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
		assert.IsType(t, &rsa.PrivateKey{}, privateKey)
		assert.Equal(t, "keyIDOne", provider.latestKeyID)
	})

	t.Run("Returns an error when failing to get the secret value", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: new(secretARN),
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
			SecretId: new(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_PRIVATE_KEY":"%s"}`, privateKeyOne) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: new(secretString),
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
			SecretId: new(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, keyIDOne) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: new(secretString),
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
		assert.IsType(t, &rsa.PrivateKey{}, privateKey)
	})

	t.Run("Returns an error when failing to get the private key", func(t *testing.T) {
		t.Parallel()
		mockSecretsManager, provider := buildMockAndProvider(t)

		input := &secretsmanager.GetSecretValueInput{
			SecretId: new(secretARN),
		}
		secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s"}`, keyIDTwo) // nolint: gosec
		output := &secretsmanager.GetSecretValueOutput{
			SecretString: new(secretString),
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
		privateKeys:     map[string]any{},
		lastUpdatedTime: time.Time{},
	}

	return mockSecretsManager, provider
}

func setUpMockWithValidSecretString(mockSecretsManager *mocks.SecretsManagerAPI, keyID, privateKey string) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: new(secretARN),
	}
	secretString := fmt.Sprintf(`{"ASAP_KEY_ID":"%s","ASAP_PRIVATE_KEY":"%s"}`, keyID, privateKey) // nolint: gosec
	output := &secretsmanager.GetSecretValueOutput{
		SecretString: new(secretString),
	}
	mockSecretsManager.On("GetSecretValue", input).Return(output, nil).Once()
}
