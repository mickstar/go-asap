# go-asap

A library that creates and verifies JSON Web Tokens (JWT) for service to service
authentication purposes using the Atlassian Service Authentication Protocol (ASAP).

[Atlassian S2S Authentication Protocol (ASAP) - Specification](https://s2sauth.bitbucket.io/)

## Getting Started

### Installing

```shell
    go get bitbucket.org/atlassian/go-asap
```

### Generating key pairs

Use OpenSSL from the command line to generate the key pairs.

```shell
    openssl genrsa -out private-key.pem 2048
    openssl rsa -in private-key.pem -pubout > public-key.pem
```

## Usage

### Generate a token for an outgoing request


```go
var privateKey, _ = asap.NewPrivateKey(os.Getenv("ASAP_PRIVATE_KEY"))
var p = asap.NewMicrosProvisioner([]string{"target_service1", "target_service1"}, time.Minute)
var token, _ = p.Provision()
var headerValue, _ = token.Serialize(privateKey)
var bearer = fmt.Sprintf("Bearer %s", string(headerValue))
```


### Validate incoming requests

To validate a token we need to two things: a way of fetching public keys for
signature verification and a set of validation rules to apply. Every service
should define its own custom validation rules and combine them with the
`DefaultValidator` which enforces the minimum ASAP requirements.

```go
var v = asap.NewValidatorChain(
  asap.NewSignatureValidator(asap.NewHTTPKeyFetcher(os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"), http.DefaultClient)),
  asap.NewAllowedAudienceValidator("myserviceid"),
  asap.DefaultValidator,
)
var token, _ = asap.ParseToken(valueFromAuthorizationHeader)
var e = v.Validate(token)
if e != nil {
  // Invalid token
}
```

If using an http mux that supports middleware you can add your validation rules
to all incoming requests via:

```go
var v = asap.NewValidatorChain(
  asap.NewSignatureValidator(asap.NewHTTPKeyFetcher(os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"), http.DefaultClient)),
  asap.NewAllowedAudienceValidator("myserviceid"),
  asap.DefaultValidator,
)

var m = asap.NewMiddleware(v, nil) // func(http.Handler) http.Handler
```
