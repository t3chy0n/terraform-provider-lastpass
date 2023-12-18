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

type BytePayloadTransformer func(payload []byte) ([]byte, error)

func cipherPkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func Transform(str string, transformers ...BytePayloadTransformer) (string, error) {
	if len(str) == 0 {
		return str, nil
	}
	var err error
	data := []byte(str)
	for _, trns := range transformers {
		data, err = trns(data)
		if err != nil {
			return "", err
		}
	}
	return string(data), nil
}

func WithHex() BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		return []byte(hex.EncodeToString(payload)), nil
	}

}

func WithUnHex() BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		if len(payload)%2 != 0 {
			return nil, errors.New("hex string has odd length")
		}

		bytes, err := hex.DecodeString(string(payload))
		if err != nil {
			// Optionally print the original hex string for debugging
			fmt.Printf("Error decoding hex string: %s\n", payload)
			return nil, err
		}

		return bytes, nil
	}
}

func WithBase64() BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		if len(payload) >= 33 && payload[0] == '!' && len(payload)%16 == 1 {
			// use the same format as the CLI
			// https://github.com/lastpass/lastpass-cli/blob/a84aa9629957033082c5930968dda7fbed751dfa/cipher.c#L296
			iv := base64.StdEncoding.EncodeToString(payload[1:17])
			encodedData := base64.StdEncoding.EncodeToString(payload[17:])
			return []byte(fmt.Sprintf("!%s|%s", iv, encodedData)), nil
		}
		return []byte(base64.StdEncoding.EncodeToString(payload)), nil
	}
}

func WithUnbase64() BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		if len(payload) == 0 {
			return nil, errors.New("empty ciphertext")
		}

		if payload[0] != '!' {
			data, err := base64.StdEncoding.DecodeString(string(payload))
			return data, err
		}

		parts := strings.SplitN(string(payload[1:]), "|", 2)
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
}

func WithAESEncrypt(key []byte) BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		if len(payload) == 0 {
			return []byte(""), nil
		}

		padded := cipherPkcs7Pad(payload, aes.BlockSize)
		ciphertext := make([]byte, aes.BlockSize+len(padded))
		iv := ciphertext[:aes.BlockSize]

		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		enc := cipher.NewCBCEncrypter(block, iv)
		enc.CryptBlocks(ciphertext[aes.BlockSize:], padded)

		return append([]byte{'!'}, append(iv, ciphertext[aes.BlockSize:]...)...), nil

	}
}

func WithAESDecrypt(key []byte) BytePayloadTransformer {
	return func(payload []byte) ([]byte, error) {
		if len(payload) == 0 {
			return nil, errors.New("empty ciphertext")
		}

		var block cipher.Block
		var err error
		var plaintext []byte
		if len(payload) >= 33 && payload[0] == '!' && len(payload)%16 == 1 {
			block, err = aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
			iv := payload[1:17]
			payload = payload[17:]
			plaintext = make([]byte, len(payload))
			blockMode := cipher.NewCBCDecrypter(block, iv)
			blockMode.CryptBlocks(plaintext, payload)

		} else {

			plaintext, err = DecryptAES_ECB(payload, key)
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
}

func WithRSADecrypt(privateKeyBytes []byte) BytePayloadTransformer {
	return func(ciphertext []byte) ([]byte, error) {
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
}
func WithRSAEncrypt(publicKeyBytes []byte) BytePayloadTransformer {
	return func(plaintext []byte) ([]byte, error) {
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
}
