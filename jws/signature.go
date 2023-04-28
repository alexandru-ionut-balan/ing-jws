package jws

import (
	"crypto/rsa"
	"encoding/json"

	"github.com/alexandru-ionut-balan/ing-jws/crypto"
	"github.com/alexandru-ionut-balan/ing-jws/logging"
	"github.com/alexandru-ionut-balan/ing-jws/util"
)

func generateHeader(jwsHeader *JwsHeader) (string, error) {
	rawHeaderBytes, err := json.Marshal(jwsHeader)
	if err != nil {
		logging.Error("Cannot marshal JWS Header into JSON.", nil)
		return "", err
	}

	return crypto.Base64(rawHeaderBytes), nil
}

func generateSignatureValue(encodedJwsHeader string, httpHeaders []util.HttpHeader, privateKey *rsa.PrivateKey) (string, error) {
	signatureInput := encodedJwsHeader + "."

	for _, header := range httpHeaders {
		signatureInput += header.Name + ": " + header.Value + "\n"
	}

	signedInput, err := crypto.Sign(signatureInput[:len(signatureInput)-1], privateKey)
	if err != nil {
		logging.Error("Cannot generate signature value.", nil)
		return "", err
	}

	return crypto.Base64(signedInput), nil
}
