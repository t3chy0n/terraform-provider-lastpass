package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"last-pass-poc/client/kdf"
	"reflect"
	"testing"
)

func TestWithHex(t *testing.T) {
	input := "test string"
	expectedOutput := "7465737420737472696e67"

	output, err := Transform(input, WithHex())
	if err != nil {
		t.Errorf("WithHex() error = %v", err)
		return
	}
	if !reflect.DeepEqual(output, expectedOutput) {
		t.Errorf("WithHex() = %v, want %v", output, expectedOutput)
	}
	old := BytesToHex([]byte(input))
	if !reflect.DeepEqual(string(old), output) {
		t.Errorf("WithHex() = %v, want %v", output, input)

	}
}

func TestHexingInvert(t *testing.T) {
	input := "test string"

	output, err := Transform(input, WithHex(), WithUnHex())
	if err != nil {
		t.Errorf("WithHex() error = %v", err)
		return
	}
	if !reflect.DeepEqual(output, input) {
		t.Errorf("WithHex() = %v, want %v", output, input)

	}
}
func TestWithBase64(t *testing.T) {
	input := "asd"
	expectedOutput := "YXNk"

	output, err := Transform(input, WithBase64())
	if err != nil {
		t.Errorf("WithBase64() error = %v", err)
		return
	}
	if !reflect.DeepEqual(output, expectedOutput) {
		t.Errorf("WithBase64() = %v, want %v", output, expectedOutput)
	}
	if !reflect.DeepEqual(CipherBase64([]byte(input)), output) {
		t.Errorf("WithHex() = %v, want %v", output, input)

	}
}

func TestBase64Invert(t *testing.T) {
	input := "test string"

	output, err := Transform(input, WithBase64(), WithUnbase64())
	if err != nil {
		t.Errorf("Tramsformation error = %v", err)
		return
	}
	if !reflect.DeepEqual(output, input) {
		t.Errorf("Tramsformation = %v, want %v", output, input)
	}
}

func TestAESInvert(t *testing.T) {
	input := "test stassaasasassdfsfd d ssd sd sd dssdsd sds sd sd ring"
	key := kdf.DecryptionKey("asd", "asd", 100)

	output, err := Transform(input, WithAESEncrypt(key), WithAESDecrypt(key))
	if err != nil {
		t.Errorf("Tramsformation error = %v", err)
		return
	}
	if !reflect.DeepEqual(output, input) {
		t.Errorf("Tramsformation = %v, want %v", output, input)
	}
}

func TestWithRSADecrypt(t *testing.T) {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)

	// Original data
	originalData := "test data"

	// Encrypt data
	transformedData, err := Transform(originalData,
		WithRSAEncrypt(publicKeyBytes),
		WithRSADecrypt(privateKeyBytes),
	)

	if err != nil {
		t.Fatalf("Failed to Transform data: %v", err)
	}

	// Compare
	if string(transformedData) != originalData {
		t.Errorf("Decrypted data does not match original. got: %s, want: %s", string(transformedData), originalData)
	}
}

func TestWithRSADecryptFailIf(t *testing.T) {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)

	// Original data
	originalData := "test data"

	// Encrypt data
	_, err = Transform(originalData,
		WithRSAEncrypt(publicKeyBytes),
		WithRSADecrypt(publicKeyBytes),
	)

	// Compare
	if err == nil {
		t.Errorf("Should not be able to decrypt with public key")
	}
}
