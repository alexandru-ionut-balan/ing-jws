package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/alexandru-ionut-balan/ing-jws/logging"
	"golang.org/x/tools/go/analysis/passes/ifaceassert"
)

func Base64(payload []byte) string {
	return base64.URLEncoding.EncodeToString(payload)
}

func Sha256(payload string) ([]byte, error) {
	hasher := sha256.New()

	_, err := hasher.Write([]byte(payload))
	if err != nil {
		fmt.Println("Cannot compute hash of the payload:" + payload)
	}
}
