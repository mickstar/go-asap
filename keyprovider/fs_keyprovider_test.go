package keyprovider

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const PUBLIC_KEY_STRING = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIXNCB3YktXiCiXiN1yR
W+Ox9IqN2aenMKG9NHdOBlwp/2BQkm+G4nRjkdfn+6XnmrLeLS6dA/gTj03tJ3YN
JoqkjAcL2+x0SU3PtDYJO29TFOvIWlq2iJyTukYdlSXLhY5U3hyv/BdgI9gd6D2T
c6sy9i3CnkKSBlPniRQC2bor5ZzCLxr7NWMfe1HsAQExw6+iGwVtaNjP4wX2kMzA
w6cPNYKsZqpjXx8/GzkralkXZvBhW6IvVQe4EZjZW8MSoK7Gb6IAV+BM0ltOasY7
OOPQvTjL/3Aj0KJSAjrpbdFzYzwpIqUpwYFKW53y9eBnd2QlarrOnOGsdRBbCctV
2QIDAQAB
-----END PUBLIC KEY-----
`

func TestReturnsPrivateKeyWhenSuccessful(t *testing.T) {

	tmpFile, err := ioutil.TempFile("./", "privatekey")
	if err != nil {
		t.Error(err)
	}

	tmpFile.WriteString(PRIVATE_KEY_STRING)
	kp := &FSKeyProvider{
		PrivateKeyPath: tmpFile.Name(),
	}

	if _, err := kp.GetPrivateKey(); err != nil {
		t.Error(err)
	}
	os.Remove(tmpFile.Name())
}

func TestReturnsErrorWhenFileDoesNotExist(t *testing.T) {
	kp := &FSKeyProvider{
		PrivateKeyPath: "./404",
	}

	if _, err := kp.GetPrivateKey(); err == nil {
		t.Error(err)
	}
}

func TestReturnsPublicKeyWithOnlyPublicKeyDir(t *testing.T) {

	tmpDir, err := ioutil.TempDir("./", "key-id")

	tmpFile, err := ioutil.TempFile(tmpDir, "public-key")
	if err != nil {
		t.Error(err)
	}

	tmpFile.WriteString(PUBLIC_KEY_STRING)
	kp := &FSKeyProvider{
		PublicKeyDir: "./",
	}

	if _, err := kp.GetPublicKey(tmpFile.Name()); err != nil {
		t.Error(err)
	}

	os.RemoveAll(tmpDir)

}

func TestReturnsPublicKeyWhenSuccessful(t *testing.T) {

	tmpDir, err := ioutil.TempDir("./", "key-id")

	tmpFile, err := ioutil.TempFile(tmpDir, "public-key")
	if err != nil {
		t.Error(err)
	}

	tmpFile.WriteString(PUBLIC_KEY_STRING)
	kp := &FSKeyProvider{
		PublicKeyDir:      "./",
		PublicKeyFilename: path.Base(tmpFile.Name()),
	}

	if _, err := kp.GetPublicKey(tmpDir); err != nil {
		t.Error(err)
	}

	os.RemoveAll(tmpDir)

}
