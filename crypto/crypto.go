package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alexandru-ionut-balan/ing-jws/logging"
)

func ApplyExtraFormatting(payload string) string {
	formattedString := strings.ReplaceAll(payload, "=", "")
	formattedString = strings.ReplaceAll(formattedString, "+", "-")
	formattedString = strings.ReplaceAll(formattedString, "/", "_")
	formattedString = strings.ReplaceAll(formattedString, "\n", "")

	return formattedString
}

func Base64(payload []byte) string {
	return base64.URLEncoding.EncodeToString(payload)
}

func Sha256(payload string) ([]byte, error) {
	hasher := sha256.New()

	_, err := hasher.Write([]byte(payload))
	if err != nil {
		fmt.Println("Cannot compute hash of the payload:" + payload)
		return nil, err
	}

	return hasher.Sum(nil), err
}

func RawSha256(payload []byte) ([]byte, error) {
	hasher := sha256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		fmt.Println("Cannot compute hash of the payload:" + string(payload))
		return nil, err
	}

	return hasher.Sum(nil), err
}

func Sign(payload string, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashedPayload, err := Sha256(payload)
	if err != nil {
		logging.Error("Cannot sign message. Hashing payload failed!", nil)
		return nil, err
	}

	signedPayload, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedPayload)
	if err != nil {
		logging.Error("Cannot sign message. Signign with private key failed!", nil)
		return nil, err
	}

	return signedPayload, nil
}
