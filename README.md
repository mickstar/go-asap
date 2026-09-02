# go-asap

A library that creates and verifies JSON Web Tokens (JWT) for service to service
authentication purposes using the Atlassian Service Authentication Protocol (ASAP).

[Atlassian S2S Authentication Protocol (ASAP) - Specification](https://s2sauth.bitbucket.io/)

## Getting Started

### Installing

```shell
    go get bitbucket.org/atlassian/go-asap/v2
```

### Generating key pairs

Use OpenSSL from the command line to generate the key pairs.

```shell
    openssl genrsa -out private-key.pem 2048
    openssl rsa -in private-key.pem -pubout > public-key.pem
```

## Usage

### Generate a token for an outgoing request

#### Original method using a static keypair

```go
privateKey, _ := asap.NewPrivateKey([]byte(os.Getenv("ASAP_PRIVATE_KEY")))
p := asap.NewMicrosProvisioner([]string{"target_service1", "target_service1"}, time.Minute)
token, _ := p.Provision()
headerValue, _ := token.Serialize(privateKey)
bearer := fmt.Sprintf("Bearer %s", string(headerValue))
```

#### New method using a dynamic autorotating keypair

The cacheTTL must be between 1 second and 2 hours (inclusive).

Also, there are two options for what to pass in for the role:
* Role - your service will assume the role
* Empty string - your service will continue using its existing role

```go
provider, _ := asap.NewSecretsManagerKeypairProvider(privateKeyARN, region, role, cacheTTL)
provisioner := asap.NewDynamicKeyIDProvisioner(ttl, issuer, audience, signingMethod, provider)

token, _ := provisioner.Provision()
keyID, _ := asap.GetKeyIDFromToken(token)
privateKey, _ := provider.Fetch(keyID)
headerValue, _ := token.Serialize(privateKey)
bearer := fmt.Sprintf("Bearer %s", string(headerValue))
```

### Validate incoming requests

Token validation needs a public-key fetcher for signature verification and a
set of validation rules. Every service should define its own rules and combine
them with `DefaultValidator`, which enforces the minimum ASAP requirements.

```go
keyFetcher, err := asap.NewExpiringCacheFetcher(
  os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"),
  http.DefaultClient,
)
if err != nil {
  // Handle invalid key repository configuration.
}

v := asap.NewValidatorChain(
  asap.DefaultValidator,
  asap.NewSignatureValidator(keyFetcher),
  asap.NewAllowedAudienceValidator("myserviceid"),
)
token, _ := asap.ParseToken(valueFromAuthorizationHeader)
err = v.Validate(token)
if err != nil {
  // Invalid token
}
```

If using an http mux that supports middleware you can add your validation rules
to all incoming requests via:

```go
v := asap.NewValidatorChain(
  asap.DefaultValidator,
  asap.NewSignatureValidator(keyFetcher),
  asap.NewAllowedAudienceValidator("myserviceid"),
)

m := asap.NewMiddleware(v, nil) // func(http.Handler) http.Handler
```

## Public key caching

Use `NewExpiringCacheFetcher` for HTTP-backed public keys. It uses response
cache headers, retains up to 1,000 entries, coalesces concurrent misses for the
same key ID, and limits stale refresh work with a fixed-size queue.
