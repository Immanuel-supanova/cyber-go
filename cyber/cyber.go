package cyber

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func EncryptAES(key []byte, plaintext string) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := c.BlockSize()
	paddedText, err := AddPKCS7Padding([]byte(plaintext), blockSize)

	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(paddedText))

	c.Encrypt(ciphertext, paddedText)

	return ciphertext, nil
}

func DecryptAES(key []byte, ct []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(ct))
	c.Decrypt(pt, ct)

	// No need to remove padding here, just return the plaintext
	return pt, nil
}

// AddPKCS7Padding adds PKCS#7 padding to the input data to make it a multiple of blockSize.
func AddPKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...), nil
}

// RemovePKCS7Padding removes PKCS#7 padding from the input data.
func RemovePKCS7Padding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("input data is empty")
	}
	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:length-padding], nil
}

func HybridEncrypt(data, pubKey string) (string, string, error) {
	key := GenerateAESKey()
	encdata, err := EncryptAES(key, data)

	if err != nil {
		return "", "", err
	}

	pubkey, err := LoadPublicKey(pubKey)
	if err != nil {
		return "", "", err
	}

	// Encrypt the message using RSA-OAEP
	enckey, err := rsa.EncryptOAEP(
		sha256.New(), // Random source
		rand.Reader,
		pubkey, // Public key
		key,    // Message to encrypt
		nil,    // Label (use nil for no label)
	)

	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(encdata), hex.EncodeToString(enckey), nil
}

func HybridDecrypt(data, key string) (string, error) {
	encdata, err := hex.DecodeString(data)

	if err != nil {
		return "", err
	}

	enckey, err := hex.DecodeString(key)

	if err != nil {
		return "", err
	}

	privkey, err := LoadPrivateKey("private_key.pem")
	if err != nil {
		return "", err
	}

	deckey, err := rsa.DecryptOAEP(
		sha256.New(), // Random source
		rand.Reader,
		privkey,
		enckey,
		nil,
	)

	if err != nil {
		return "", err
	}

	decdata, err := DecryptAES(deckey, encdata)

	if err != nil {
		return "", err
	}

	unpaddedData, err := RemovePKCS7Padding([]byte(decdata))

	if err != nil {
		return "", err
	}

	return string(unpaddedData), nil
}
