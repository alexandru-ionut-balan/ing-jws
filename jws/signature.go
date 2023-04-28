package jws

import (
	"encoding/json"

	"github.com/alexandru-ionut-balan/ing-jws/crypto"
	"github.com/alexandru-ionut-balan/ing-jws/logging"
)

func generateHeader(jwsHeader *JwsHeader) (string, error) {
	rawHeaderBytes, err := json.Marshal(jwsHeader)
	if err != nil {
		logging.Error("Cannot marshal JWS Header into JSON.", nil)
		return "", err
	}

	return crypto.Base64(rawHeaderBytes), nil
}
