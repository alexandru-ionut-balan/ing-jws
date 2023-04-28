package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

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
