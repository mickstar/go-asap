package keyprovider

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestReturnsPrivateKeyWhenSuccessful(t *testing.T) {
	tmpFile, err := ioutil.TempFile("./", "privatekey")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(PrivateKeyString); err != nil {
		t.Fatal(err)
	}

	kp := &FSKeyProvider{
		PrivateKeyPath: tmpFile.Name(),
	}

	if _, err := kp.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}
}

func TestReturnsErrorWhenFileDoesNotExist(t *testing.T) {
	kp := &FSKeyProvider{
		PrivateKeyPath: "./404",
	}

	if _, err := kp.GetPrivateKey(); err == nil {
		t.Fatal(err)
	}
}

func TestReturnsPublicKeyWithOnlyPublicKeyDir(t *testing.T) {
	tmpDir, err := ioutil.TempDir("./", "key-id")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile, err := ioutil.TempFile(tmpDir, "public-key")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile.WriteString(PublicKeyString)
	kp := &FSKeyProvider{
		PublicKeyDir: "./",
	}

	if _, err := kp.GetPublicKey(tmpFile.Name()); err != nil {
		t.Fatal(err)
	}
}

func TestReturnsPublicKeyWhenSuccessful(t *testing.T) {
	tmpDir, err := ioutil.TempDir("./", "key-id")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile, err := ioutil.TempFile(tmpDir, "public-key")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tmpFile.WriteString(PublicKeyString); err != nil {
		t.Fatal(err)
	}

	kp := &FSKeyProvider{
		PublicKeyDir:      "./",
		PublicKeyFilename: path.Base(tmpFile.Name()),
	}

	if _, err := kp.GetPublicKey(tmpDir); err != nil {
		t.Fatal(err)
	}
}
