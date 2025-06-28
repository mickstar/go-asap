package asap

import (
	"encoding/json"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
)

var (
	IAMRoleArnRegex = regexp.MustCompile(`^arn:(aws|aws-us-gov):iam::([0-9]{12}):role\/([^\/]+)$`)
)

type SecretsManagerAPI interface {
	GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}

type SecretsManagerKeypairProvider struct {
	client        SecretsManagerAPI
	privateKeys   map[string]string
	privateKeyARN string
}

func NewSecretsManagerKeypairProvider(privateKeyARN string, region string, role string) (*SecretsManagerKeypairProvider, error) {
	err := validateTheInput(region, role)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid input; region: %s; role: %s", region, role)
	}

	secretsManagerClient := buildTheSecretsManagerClient(region, role)
	provider := &SecretsManagerKeypairProvider{
		client:        secretsManagerClient,
		privateKeys:   map[string]string{},
		privateKeyARN: privateKeyARN,
	}

	return provider, nil
}

func (p *SecretsManagerKeypairProvider) GetKeyID() (string, error) {
	secretValue, err := p.getTheSecretValue()
	if err != nil {
		return "", errors.Wrapf(err, "Failed to get the secret value from Secrets Manager; privateKeyARN: %s", p.privateKeyARN)
	}

	keyID, exists := secretValue["ASAP_KEY_ID"]
	if !exists {
		return "", errors.Errorf("Failed to get the keyID from the secret value; privateKeyARN: %s", p.privateKeyARN)
	}

	privateKey, exists := secretValue["ASAP_PRIVATE_KEY"]
	if !exists {
		return "", errors.Errorf("Failed to get the private key from the secret value; privateKeyARN: %s", p.privateKeyARN)
	}

	p.privateKeys[keyID] = privateKey

	return keyID, nil
}

func (p *SecretsManagerKeypairProvider) Fetch(keyID string) (interface{}, error) {
	privateKey, exists := p.privateKeys[keyID]
	if !exists {
		return nil, errors.Errorf("Failed to get the private key from the map; keyID: %s", keyID)
	}

	return privateKey, nil
}

func (p *SecretsManagerKeypairProvider) getTheSecretValue() (map[string]string, error) {
	getSecretValueInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(p.privateKeyARN),
	}

	result, err := p.client.GetSecretValue(getSecretValueInput)
	if err != nil {
		return nil, handleClientError(err, "Failed to get the secret value", "privateKeyARN: "+p.privateKeyARN)
	}

	if result.SecretString == nil {
		return nil, errors.Errorf("Secret string is nil; privateKeyARN: %s", p.privateKeyARN)
	}

	var secretValue map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &secretValue); err != nil {
		return nil, errors.Wrapf(err, "Failed to parse the secret string; privateKeyARN: %s", p.privateKeyARN)
	}

	return secretValue, nil
}

func validateTheInput(region string, role string) error {
	if region == "" {
		return errors.New("The region is empty")
	}

	if role == "" {
		return errors.New("The role ARN is empty")
	}

	if !IAMRoleArnRegex.MatchString(role) {
		return errors.Errorf("The role is not a valid AWS IAM ARN; role: %s", role)
	}

	return nil
}

func buildTheSecretsManagerClient(region string, role string) SecretsManagerAPI {
	useFIPSEndpoint := endpoints.FIPSEndpointStateDisabled
	if os.Getenv("AWS_USE_FIPS_ENDPOINT") == "true" {
		useFIPSEndpoint = endpoints.FIPSEndpointStateEnabled
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigDisable,
		Config: aws.Config{
			UseFIPSEndpoint: useFIPSEndpoint,
			Region:          aws.String(region),
		},
	}))

	conf := &aws.Config{}
	conf.Credentials = stscreds.NewCredentials(sess, role)

	client := secretsmanager.New(sess, conf)

	return client
}

func handleClientError(err error, msg string, input interface{}) error {
	awsErrCode := ""
	errMessage := err.Error()

	if aerr, ok := err.(awserr.Error); ok {
		awsErrCode = aerr.Code()
		errMessage = aerr.Message()
	}

	return errors.Wrapf(err, "%s; awsErrorCode: %s; errorMessage: %s; input: %v", msg, awsErrCode, errMessage, input)
}
