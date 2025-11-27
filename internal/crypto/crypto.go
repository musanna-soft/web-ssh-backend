package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

var encryptionKey []byte

func Init() {
	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		fmt.Println("WARNING: ENCRYPTION_KEY not set, using a random key (data will be lost on restart)")
		encryptionKey = make([]byte, 32)
		rand.Read(encryptionKey)
	} else {
		// Ensure key is 32 bytes (256 bits)
		if len(key) != 32 {
			// In a real app, handle this better (e.g., hash the key)
			// For now, we assume the user provides a 32-byte key or we pad/truncate
			k := make([]byte, 32)
			copy(k, []byte(key))
			encryptionKey = k
		} else {
			encryptionKey = []byte(key)
		}
	}
}

func Encrypt(text string) (string, error) {
	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(text), nil)), nil
}

func Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
