package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	LP_PKEY_PREFIX = "LastPassPrivateKey<"
	LP_PKEY_SUFFIX = ">LastPassPrivateKey"
)

func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func HexToBytes(hexStr []byte) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, errors.New("hex string has odd length")
	}

	bytes, err := hex.DecodeString(string(hexStr))
	if err != nil {
		// Optionally print the original hex string for debugging
		fmt.Printf("Error decoding hex string: %s\n", hexStr)
		return nil, err
	}

	return bytes, nil
}

func CipherBase64(data []byte) string {
	if len(data) >= 33 && data[0] == '!' && len(data)%16 == 1 {
		iv := base64.StdEncoding.EncodeToString(data[1:17])
		encodedData := base64.StdEncoding.EncodeToString(data[17:])
		return fmt.Sprintf("!%s|%s", iv, encodedData)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func DecryptAES_ECB(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	for start := 0; start < len(ciphertext); start += aes.BlockSize {
		end := start + aes.BlockSize
		block.Decrypt(plaintext[start:end], ciphertext[start:end])
	}

	return plaintext, nil
}
func EncryptAES_ECB(plaintext, key []byte) ([]byte, error) {
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	if len(padded)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(padded))
	for start := 0; start < len(padded); start += aes.BlockSize {
		end := start + aes.BlockSize
		block.Encrypt(ciphertext[start:end], padded[start:end])
	}

	return ciphertext, nil
}
func CipherAESEncrypt(plaintext string, key []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(padded))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	enc := cipher.NewCBCEncrypter(block, iv)
	enc.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext[aes.BlockSize:])

	// use the same format as the CLI
	// https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/cipher.c#L296
	return fmt.Sprintf("!%s|%s", ivBase64, ciphertextBase64), nil
}

func CipherAESDecrypt(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	var block cipher.Block
	var err error
	var plaintext []byte
	if len(ciphertext) >= 33 && ciphertext[0] == '!' && len(ciphertext)%16 == 1 {
		block, err = aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		iv := ciphertext[1:17]
		ciphertext = ciphertext[17:]
		plaintext = make([]byte, len(ciphertext))
		blockMode := cipher.NewCBCDecrypter(block, iv)
		blockMode.CryptBlocks(plaintext, ciphertext)

	} else {

		plaintext, err = DecryptAES_ECB(ciphertext, key)
		if err != nil {
			return nil, err
		}
	}
	textLen := len(plaintext)

	//Remove padding
	padding := int(plaintext[textLen-1])
	if padding > textLen {
		return nil, errors.New("CipherAESDecrypt padding: invalid padding size for attach key")
	}

	return plaintext[:textLen-padding], nil
}

func CipherRSADecrypt(ciphertext []byte, privateKeyBytes []byte) ([]byte, error) {
	// Parse the private key
	priv, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Type assert to *rsa.Key
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}

	// Decrypt the data
	decryptedData, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaPriv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}
func CipherRSAEncrypt(plaintext []byte, publicKeyBytes []byte) ([]byte, error) {
	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	// Type assert to *rsa.PublicKey
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	// Encrypt the data
	encryptedData, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}
func CipherUnbase64(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	if ciphertext[0] != '!' {
		data, err := base64.StdEncoding.DecodeString(string(ciphertext))
		return data, err
	}

	parts := strings.SplitN(string(ciphertext[1:]), "|", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid format")
	}

	iv, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	return append([]byte{'!'}, append(iv, data...)...), nil
}

func CipherAESDecryptBase64(ciphertext []byte, key []byte) ([]byte, error) {
	unbase64Ciphertext, err := CipherUnbase64(ciphertext)
	if err != nil {
		return nil, err
	}

	return CipherAESDecrypt(unbase64Ciphertext, key)
}

func CipherDecryptPrivateKey(keyHex []byte, key []byte) ([]byte, error) {
	if len(keyHex) == 0 {
		return nil, nil
	}

	var decryptedKey []byte
	var err error

	if keyHex[0] == '!' {
		// v2 format
		decryptedKey, err = CipherAESDecryptBase64(keyHex, key[:]) // Implement cipherAESDecryptBase64
		if err != nil {
			return nil, err
		}
	} else {
		if len(keyHex)%2 != 0 {
			return nil, errors.New("key hex in wrong format")
		}

		encryptedKeyBytes, err := HexToBytes(keyHex)

		if err != nil {
			return nil, err
		}

		// Prepend '!' and IV
		ivAndEncryptedKey := append([]byte{'!'}, append(key[:16], encryptedKeyBytes...)...)

		decryptedKey, err = CipherAESDecrypt(ivAndEncryptedKey, key[:])
		if err != nil {
			return nil, err
		}
	}

	start := strings.Index(string(decryptedKey), LP_PKEY_PREFIX)
	end := strings.Index(string(decryptedKey), LP_PKEY_SUFFIX)
	if start == -1 || end == -1 || end <= start {
		return nil, errors.New("could not decode decrypted private key")
	}

	hexKey := decryptedKey[start+len(LP_PKEY_PREFIX) : end]
	decKey, err := hex.DecodeString(string(hexKey))
	if err != nil {
		return nil, err
	}

	return decKey, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}
