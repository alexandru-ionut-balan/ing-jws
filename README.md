# JWICE

Jwice is a small and incomplete library for creating jws signatures. 
The main purpose of this library is to explore the logic behind creating these signatures and use it in
the [Demogog](https://github.com/alxandru-ionut-balan/demogog) application.

## Usage

You can either use the default header and change from there or create a new protected header from
scratch by creating a new object of type `jws.JwsProtectedHeader`

To use the default just do:

```go
// ...
// certificate 	-- x509.Certificate
// httpHeaders 	-- http.HttpHeader
// privateKey 	-- *rsa.PrivateKey
// ...

protectedHeader := jws.DefaultJwsProtectedHeader().WithCertificate(certificate)
signature, err := jws.GenerateSignature(protectedHeader, httpHeaders, privateKey)
```

The default header has the following properties set:

```go
JwsProtectedHeader{
	B64:  false,
	Crit: []string{"sigT", "sigD", "b64"},
	Alg:  "RS256",
	SigT: time.Now().In(time.UTC).Format(time.RFC3339),
	SigD: SignedHeaders{
		Pars: []string{"(request-target)", "digest"},
		MId:  "http://uri.etsi.org/19182/HttpHeaders",
	},
}
```

When defining your protected header it is easy to chain multiple functions that mutate the header:

```go
protectedHeader := jws.DefaultJwsProtectedHeader().
	WithCertificate(certificate).
	WithSigningAlgorithm(jws.SHA_512).
	WithClaimedTime(time.Now().Add(5 * time.Minute)).
	WithSignedHeaders([]string{"digest", "date", "content-type", "x-custom-something"})
```

## Sugary bits

The library will do the following things for you:
	- When using ```go *JwsProtectedHeader.WithClaimedTime(time time.Time)``` the function will transform your time to UTC and format it according to RFC3339.
	- When using ```go *JwsProtectedHeader.WithSignedHeader(headers []string)``` you can specify which HTTP Headers you are going to include in this signature. The function will eliminate duplicates and format the resulting slice so each element is lowercase. **NOTE: digest and (request-target) headers are mandatory.**
	- Based on the Alg field set in the protected header, when generating the signature, **Jwice** will apply the correct hashing algorithm.
