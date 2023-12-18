package kdf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"strings"
)

const (
	KDFHashLen = 32
)

func Sha256Hash(data, key string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	h.Write([]byte(key))
	return h.Sum(nil)
}
func Pbkdf2Hash(username string, password string, iterations int) []byte {
	if iterations <= 0 {
		return nil
	}

	// Convert username and password to byte slices
	usernameBytes := []byte(username)
	passwordBytes := []byte(password)

	// Generate the PBKDF2 hash
	hash := pbkdf2.Key(passwordBytes, usernameBytes, iterations, KDFHashLen, sha256.New)

	return hash
}

func LoginKey(username string, password string, iterations int) []byte {

	userLower := strings.ToLower(username)

	if iterations < 1 {
		iterations = 1
	}

	var hash []byte

	if iterations == 1 {
		hash = Sha256Hash(userLower, password)
		hexStr := hex.EncodeToString(hash)
		hash = Sha256Hash(hexStr, password)
	} else {
		hash = Pbkdf2Hash(userLower, password, iterations)
		hash = Pbkdf2Hash(password, string(hash), 1)
	}

	return hash
}

func DecryptionKey(username string, password string, iterations int) []byte {

	userLower := strings.ToLower(username)

	if iterations < 1 {
		iterations = 1
	}

	if iterations == 1 {
		return Sha256Hash(userLower, password)
	} else {
		return Pbkdf2Hash(userLower, password, iterations)
	}

}

const ALLOWED_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$"

func RandomString(size int) string {
	var result string
	for i := 0; i < size; i++ {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ALLOWED_CHARACTERS))))
		result += string(ALLOWED_CHARACTERS[index.Int64()])
	}
	return result
}

// Generate attachkey in byte and hex form
func GenerateAttachmentKey() ([]byte, string) {

	ivkey := RandomString(20)
	pass := RandomString(20)
	attachKey := DecryptionKey(ivkey, pass, 1)
	attachKeyHex := hex.EncodeToString(attachKey)

	return attachKey, attachKeyHex
}

func CalculateTrustID(force bool) (string, error) {
	//TODO: Should allow different read/write storage to persist this token.
	//trustedID := config.ReadString("trusted_id")
	//
	//if force && trustedID == "" {
	var trustedID = RandomString(32)
	//config.WriteString("trusted_id", trustedID)
	//}

	return trustedID, nil
}
