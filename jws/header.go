package jws

import (
	"crypto/x509"
	"time"

	"github.com/alexandru-ionut-balan/ing-jws/crypto"
	"github.com/alexandru-ionut-balan/ing-jws/logging"
)

type JwsHeader struct {
	B64  bool          `json:"b64"`
	S256 string        `json:"x5t#S256"`
	Crit []string      `json:"crit"`
	SigT string        `json:"sigT"`
	SigD SignedHeaders `json:"sigD"`
	Alg  string        `json:"alg"`
}

type SignedHeaders struct {
	Pars []string `json:"pars"`
	MId  string   `json:"mId"`
}

func DefaultJwsHeader() *JwsHeader {
	return &JwsHeader{
		B64:  false,
		Crit: []string{"sigT", "sigD", "b64"},
		Alg:  "RS256",
		SigD: SignedHeaders{
			Pars: []string{"(request-target)", "digest"},
			MId:  "http://uri.etsi.org/19182/HttpHeaders",
		},
	}
}

func (jh *JwsHeader) WithB64(b64 bool) *JwsHeader {
	jh.B64 = b64
	return jh
}

func (jh *JwsHeader) WithCertificate(certificate x509.Certificate) *JwsHeader {
	fingerprint, err := crypto.RawSha256(certificate.Raw)
	if err != nil {
		logging.Error("Cannot fill S256 (x5t#S256) header value beacuse certificate fingerprint could not be determined.", err)
		return jh
	}

	jh.S256 = crypto.ApplyExtraFormatting(crypto.Base64(fingerprint))
	return jh
}

func (jh *JwsHeader) WithCrit(criticalFields []string) *JwsHeader {
	jh.Crit = criticalFields
	return jh
}

func (jh *JwsHeader) WithClaimedTime(claimedTime time.Time) *JwsHeader {
	formattedTime := claimedTime.In(time.UTC).Format(time.RFC3339)
	jh.SigT = formattedTime
	return jh
}

func (jh *JwsHeader) WithSignedHeaders(headers []string) *JwsHeader {
	newHeaders := set(lowerAll(headers))
	jh.SigD.Pars = newHeaders
	return jh
}

func (jh *JwsHeader) WithSigningAlgorithm(algorithm string) *JwsHeader {
	jh.Alg = algorithm
	return jh
}
