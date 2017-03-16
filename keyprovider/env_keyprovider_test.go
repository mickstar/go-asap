package keyprovider

import (
	"os"
	"testing"
)

func TestSucceedsWhenPrivateKeyReadFromEnvironmentVariable(t *testing.T) {
	os.Setenv(PrivateKeyKey, PrivateKeyString)
	defer os.Unsetenv(PrivateKeyKey)
	kp := &EnvironmentPrivateKeyProvider{
		PrivateKeyEnvName: PrivateKeyKey,
	}

	if _, err := kp.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}
}

func TestFailsWhenNoEnvironmentVariableProvided(t *testing.T) {
	kp := &EnvironmentPrivateKeyProvider{}

	if _, err := kp.GetPrivateKey(); err == nil {
		t.Fatal("error not returned")
	}
}

func TestFailsWhenNoPrivateKeySetInEnvironmentVariable(t *testing.T) {
	kp := &EnvironmentPrivateKeyProvider{
		PrivateKeyEnvName: PrivateKeyKey,
	}

	if _, err := kp.GetPrivateKey(); err == nil {
		t.Fatal("error not returned")
	}
}
