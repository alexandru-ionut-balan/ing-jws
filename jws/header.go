package jws

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
