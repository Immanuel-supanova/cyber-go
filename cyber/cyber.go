package cyber

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

func EncryptGCMAES(key []byte, plaintext string) ([]byte, []byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return ciphertext, nonce, nil
}

func DecryptGCMAES(key []byte, nonce []byte, ct []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}

	pt := make([]byte, len(ct))
	c.Decrypt(pt, ct)

	return plaintext, nil
}

func HybridEncrypt(data, pubKey string) (string, string, string, error) {
	key := GenerateAESKey()
	encdata, nonce, err := EncryptGCMAES(key, data)

	if err != nil {
		return "", "", "", err
	}

	pubkey, err := LoadPublicKey(pubKey)
	if err != nil {
		return "", "", "", err
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
		return "", "", "", err
	}

	return hex.EncodeToString(encdata), hex.EncodeToString(enckey), hex.EncodeToString(nonce), nil
}

func HybridDecrypt(data, nonce, key string) (string, error) {
	encdata, err := hex.DecodeString(data)

	if err != nil {
		return "", err
	}

	encnonce, err := hex.DecodeString(nonce)

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

	decdata, err := DecryptGCMAES(deckey, encnonce, encdata)

	if err != nil {
		return "", err
	}

	return string(decdata), nil
}

func EncryptAESFromPEM(plaintext string) ([]byte, []byte, error) {
	// Load AESKey
	aesKey, err := LoadAESKey("aes_key.pem")
	if err != nil {
		return nil, nil, err
	}

	// Encrypt message
	aesencData, nonce, err := EncryptGCMAES(aesKey, plaintext)
	if err != nil {
		return nil, nil, err
	}

	return aesencData, nonce, err

}

func DecryptAESFromPEM(ct, nonce []byte) ([]byte, error) {
	// Load AESKey
	aesKey, err := LoadAESKey("aes_key.pem")
	if err != nil {
		return nil, err
	}

	// Encrypt message
	aesdecData, err := DecryptGCMAES(aesKey, nonce, ct)
	if err != nil {
		return nil, err
	}

	return aesdecData, err
}
