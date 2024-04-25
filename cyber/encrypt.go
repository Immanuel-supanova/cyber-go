package cyber

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
