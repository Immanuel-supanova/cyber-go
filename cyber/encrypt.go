package cyber

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func GenerateAESKey() []byte {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err := rand.Read(key)
	if err != nil {
		panic(err.Error())
	}
	return key
}

func GenerateRSAKeys() (*rsa.PrivateKey, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func SaveKeyToPEM(key interface{}, filePath string) error {
	// Create the file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create PEM block
	var pemBlock *pem.Block
	switch key := key.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
	case *rsa.PublicKey:
		pemBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pemBytes,
		}
	default:
		return fmt.Errorf("unsupported key type")
	}

	// Write PEM block to file
	err = pem.Encode(file, pemBlock)
	if err != nil {
		return err
	}
	return nil
}

func CreateRSAKeyFile() {
	privateFilePath := "private_key.pem"

	_, err := os.Stat(privateFilePath)

	if os.IsNotExist(err) {
		privateKey, err := GenerateRSAKeys()
		if err != nil {
			fmt.Println("Error generating RSA keys:", err)
			return
		}

		// Save private key to .pem file
		err = SaveKeyToPEM(privateKey, "private_key.pem")
		if err != nil {
			fmt.Println("Error saving private key:", err)
			return
		}

	} else {
		return
	}
}

func CreateAESKeyFile() {
	aesFilePath := "aes_key.pem"

	_, err := os.Stat(aesFilePath)

	if os.IsNotExist(err) {
		aesKey := GenerateAESKey()

		// Encode key to PEM format
		block := &pem.Block{
			Type:  "AES KEY",
			Bytes: aesKey,
		}

		// Write PEM encoded key to a file
		file, err := os.Create(aesFilePath)
		if err != nil {
			fmt.Println("Error generating AES key file:", err)
			return
		}
		defer file.Close()

		err = pem.Encode(file, block)
		if err != nil {
			fmt.Println("Error Writing AES key to file:", err)
			return
		}

	} else {
		return
	}
}

func LoadPrivateKey(filepath string) (*rsa.PrivateKey, error) {
	// Read the PEM file
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// Decode PEM data
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, err
	}

	// Parse the RSA private key
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func LoadPublicKey(pemString string) (*rsa.PublicKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Type assert to *rsa.PublicKey
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, err
	}

	return rsaPublicKey, nil
}

func LoadAESKey(filename string) ([]byte, error) {
	// Read the PEM file
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Check if the PEM block type is "AES KEY"
	if block.Type != "AES KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	// Extract the AES key
	key := block.Bytes

	return key, nil
}

func PublicKeyPem(pubkey any) (string, error) {
	// Convert the public key to DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}

	// Create a PEM block for the public key
	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	}

	// Encode the PEM block to a string
	pemString := string(pem.EncodeToMemory(pemBlock))

	return pemString, nil
}
