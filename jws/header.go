package jws

import (
	"crypto/x509"
	"time"

	"github.com/alexandru-ionut-balan/jwice/crypto"
	"github.com/alexandru-ionut-balan/jwice/logging"
)

type SigningAlgorithm string

const (
	SHA_256 SigningAlgorithm = "RS256"
	SHA_512 SigningAlgorithm = "RS512"
)

type JwsProtectedHeader struct {
	B64  bool             `json:"b64"`
	S256 string           `json:"x5t#S256"`
	Crit []string         `json:"crit"`
	SigT string           `json:"sigT"`
	SigD SignedHeaders    `json:"sigD"`
	Alg  SigningAlgorithm `json:"alg"`
}

type SignedHeaders struct {
	Pars []string `json:"pars"`
	MId  string   `json:"mId"`
}

func DefaultJwsProtectedHeader() *JwsProtectedHeader {
	return &JwsProtectedHeader{
		B64:  false,
		Crit: []string{"sigT", "sigD", "b64"},
		Alg:  "RS256",
		SigT: time.Now().In(time.UTC).Format(time.RFC3339),
		SigD: SignedHeaders{
			Pars: []string{"(request-target)", "digest"},
			MId:  "http://uri.etsi.org/19182/HttpHeaders",
		},
	}
}

func (jh *JwsProtectedHeader) WithB64(b64 bool) *JwsProtectedHeader {
	jh.B64 = b64
	return jh
}

func (jh *JwsProtectedHeader) WithCertificate(certificate x509.Certificate) *JwsProtectedHeader {
	fingerprint, err := crypto.Sha256(certificate.Raw)
	if err != nil {
		logging.Error("Cannot fill S256 (x5t#S256) header value beacuse certificate fingerprint could not be determined.", err)
		return jh
	}

	jh.S256 = crypto.Base64(fingerprint)
	return jh
}

func (jh *JwsProtectedHeader) WithCrit(criticalFields []string) *JwsProtectedHeader {
	jh.Crit = criticalFields
	return jh
}

func (jh *JwsProtectedHeader) WithClaimedTime(claimedTime time.Time) *JwsProtectedHeader {
	formattedTime := claimedTime.In(time.UTC).Format(time.RFC3339)
	jh.SigT = formattedTime
	return jh
}

func (jh *JwsProtectedHeader) WithSignedHeaders(headers []string) *JwsProtectedHeader {
	newHeaders := set(lowerAll(headers))
	jh.SigD.Pars = newHeaders
	return jh
}

func (jh *JwsProtectedHeader) WithSigningAlgorithm(algorithm SigningAlgorithm) *JwsProtectedHeader {
	jh.Alg = algorithm
	return jh
}
