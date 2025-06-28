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

func NewSecretsManagerKeypairProvider(region string, role string) (*SecretsManagerKeypairProvider, error) {
	// input validation
	if region == "" {
		return nil, errors.New("The region is empty")
	}

	if role == "" {
		return nil, errors.New("The role ARN is empty")
	}

	if !IAMRoleArnRegex.MatchString(role) {
		return nil, errors.Errorf("The role is not a valid AWS IAM ARN; role: %s", role)
	}

	// build the Secrets Manager client
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

	awsClient := secretsmanager.New(sess, conf)

	provider := &SecretsManagerKeypairProvider{
		client: awsClient,
	}

	// create a map
	provider.privateKeys = map[string]string{}

	return provider, nil
}

func (p *SecretsManagerKeypairProvider) GetKeyID() (string, error) {
	// get the secret value from Secrets Manager
	getSecretValueInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(p.privateKeyARN),
	}

	result, err := p.client.GetSecretValue(getSecretValueInput)
	if err != nil {
		return "", handleClientError(err, "Failed to get the secret value", "privateKeyARN: "+p.privateKeyARN)
	}

	if result.SecretString == nil {
		return "", errors.Errorf("Secret string is nil; privateKeyARN: %s", p.privateKeyARN)
	}

	var secretValue map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &secretValue); err != nil {
		return "", errors.Wrapf(err, "Failed to parse the secret string; privateKeyARN: %s", p.privateKeyARN)
	}

	// get the keyID and private key from the secret value
	keyID, exists := secretValue["ASAP_KEY_ID"]
	if !exists {
		return "", errors.Errorf("Failed to get the keyID from the secret value; privateKeyARN: %s", p.privateKeyARN)
	}

	privateKey, exists := secretValue["ASAP_PRIVATE_KEY"]
	if !exists {
		return "", errors.Errorf("Failed to get the private key from the secret value; privateKeyARN: %s", p.privateKeyARN)
	}

	// put the private key in the map
	p.privateKeys[keyID] = privateKey

	return keyID, nil
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
