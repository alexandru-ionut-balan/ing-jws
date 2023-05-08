package jws

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/alexandru-ionut-balan/jwice/crypto"
	"github.com/alexandru-ionut-balan/jwice/logging"
)

func generateEncodedHeader(jwsHeader *JwsProtectedHeader) (string, error) {
	rawHeaderBytes, err := json.Marshal(jwsHeader)
	logging.Info("Encoding jws header: " + string(rawHeaderBytes))
	if err != nil {
		logging.Error("Cannot marshal JWS Header into JSON.", nil)
		return "", err
	}

	return crypto.Base64(rawHeaderBytes), nil
}

func generateSignatureValue(encodedJwsHeader string, algorithm SigningAlgorithm, sigD []string, httpHeaders map[string]string, privateKey *rsa.PrivateKey) (string, error) {
	signatureInput := encodedJwsHeader + "."

	for _, name := range sigD {
		value, ok := httpHeaders[name]
		if !ok {
			logging.Error("No http header was found for header name: "+name, nil)
			return "", errors.New("header name present in sigD, but missing when generating signature")
		}

		signatureInput += name + ": " + value + "\n"
	}
	signatureInput = signatureInput[:len(signatureInput)-1]

	logging.Info("Signing jws value: " + signatureInput)

	hashedPayload, err := hashPayload(signatureInput, algorithm)
	if err != nil {
		logging.Error("Cannot sign message. Hashing payload failed!", nil)
		return "", err
	}

	signedInput, err := crypto.Sign(hashedPayload, privateKey)
	if err != nil {
		logging.Error("Cannot generate signature value.", nil)
		return "", err
	}

	return crypto.Base64(signedInput), nil
}

func hashPayload(payload string, algorithm SigningAlgorithm) ([]byte, error) {
	switch algorithm {
	case SHA_256:
		return crypto.Sha256([]byte(payload))
	case SHA_512:
		return crypto.Sha512([]byte(payload))
	default:
		return crypto.Sha256([]byte(payload))
	}
}

func parseHttpHeaders(httpHeaders http.Header) map[string]string {
	headerMap := map[string]string{}

	for key, valueArray := range httpHeaders {
		headerMap[strings.ToLower(key)] = strings.Join(valueArray, ",")
	}

	return headerMap
}

func GenerateSignature(jwsHeader *JwsProtectedHeader, httpHeaders http.Header, privateKey *rsa.PrivateKey) (string, error) {
	encodedHeader, err := generateEncodedHeader(jwsHeader)
	if err != nil {
		logging.Error("Cannot create signature!", nil)
		return "", err
	}

	parsedHttpHeaders := parseHttpHeaders(httpHeaders)

	signatureValue, err := generateSignatureValue(encodedHeader, jwsHeader.Alg, jwsHeader.SigD.Pars, parsedHttpHeaders, privateKey)
	if err != nil {
		logging.Error("Cannot create signature!", nil)
		return "", err
	}

	return encodedHeader + ".." + signatureValue, nil
}
