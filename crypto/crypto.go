package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"

	"github.com/alexandru-ionut-balan/jwice/logging"
)

func Base64(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload)
}

func Sha256(payload []byte) ([]byte, error) {
	hasher := sha256.New()

	_, err := hasher.Write(payload)
	if err != nil {
		logging.Warn("Cannot compute hash of the payload: " + string(payload))
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func Sha512(payload []byte) ([]byte, error) {
	hasher := sha512.New()

	if _, err := hasher.Write(payload); err != nil {
		logging.Warn("Cannot compute hash of the payload: " + string(payload))
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func Sign(payload []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	signedPayload, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, payload)
	if err != nil {
		logging.Error("Cannot sign message. Signign with private key failed!", nil)
		return nil, err
	}

	return signedPayload, nil
}
