# JWICE

Jwice is a small and incomplete library for creating jws signatures. 
The main purpose of this library is to explore the logic behind creating these signatures and use it in
the [Demogog](https://github.com/alxandru-ionut-balan/demogog) application.

## Usage

You can either use the default header and change from there or create a new protected header from
scratch.

To use the default just do:

```go
protectedHeader := jws.DefaultJwsProtectedHeader()
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
