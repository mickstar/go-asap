# go-asap

**Experimental fork. Not for production use.**

This is a personal fork of Atlassian's internal `go-asap` v2 module. It is
published as an experiment in dependency migration, not as a maintained
library. There is no support, no guarantee of API stability, and no claim that
the reasoning in it has been reviewed by anyone other than its author. If you
need ASAP token handling for real, use a maintained implementation and have your
own security team review it.

## What it is

A library that creates and verifies JSON Web Tokens (JWT) for service-to-service
authentication purposes using the Atlassian Service Authentication Protocol
(ASAP).

[Atlassian S2S Authentication Protocol (ASAP) - Specification](https://s2sauth.bitbucket.io/)

## Why this fork exists

Upstream depended on `github.com/SermoDigital/jose`, which has been unmaintained
since 2016 and **panics at package init on Go 1.27**:

```
panic: crypto: RegisterHash of unknown hash function
  github.com/SermoDigital/jose/crypto.init.0()
    .../jose@v0.9.2-.../crypto/none.go:11
```

Any test binary or program importing the package therefore cannot start on a
current toolchain. This fork replaces jose with
[`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) and deletes
the superseded v1 root module.

Behaviour was held fixed against a frozen oracle rather than re-derived: before
the migration, `tools/paritygen` recorded exactly what the jose-based library
did (parse verdicts, protected headers, canonical claims, and the verdicts of
the real `DefaultValidator` and `SignatureValidator`) into
`testdata/parity/`. The test suite replays those fixtures, so the migration is
verified against the old behaviour rather than against a reading of the JWT
spec. See [Testing](#testing).

[`MIGRATION.md`](MIGRATION.md) is the full report: the root cause, the
compatibility layer, every deliberate divergence, the defects found along the
way, and the evidence behind each claim.

## Installing

```shell
    go get github.com/mickstar/go-asap
```

## Compatibility with the Atlassian module

The wire format and validation behaviour are preserved. The Go API changes where
jose types were exposed, because jose cannot be imported on Go 1.27:

| Before (`bitbucket.org/atlassian/go-asap/v2`) | After |
| --- | --- |
| `crypto.SigningMethodRS256` (jose) | `asap.SigningMethodRS256` |
| `asap.NewProvisioner(..., crypto.SigningMethod)` | `asap.NewProvisioner(..., asap.SigningMethod)` |
| `asap.NewDynamicKeyIDProvisioner(..., crypto.SigningMethod, ...)` | `asap.NewDynamicKeyIDProvisioner(..., asap.SigningMethod, ...)` |
| `token.(jws.JWS).Protected().Get("kid")` | `token.Protected().Get("kid")` |
| `jwt.Validator{EXP: d, NBF: d}` | `asap.ValidationOptions{EXP: d, NBF: d}` |
| `jwt.Claims` / `jws.Claims` | `asap.Claims` |
| `jwt.ErrTokenIsExpired` | `asap.ErrTokenIsExpired` |

`asap.Token` is now a self-contained interface (`Claims`, `Protected`,
`Serialize`, `Validate`). Everything else in the documented API is unchanged,
including `NewMicrosProvisioner`, the key parsers, the fetchers, the middleware
and the token caches.

### ECDSA tokens are not interoperable with the old stack

The oracle caught a genuine defect in jose v0.9.2. For `ES256`, `ES384` and
`ES512` it emitted an ASN.1/DER encoded ECDSA signature, whereas RFC 7518
section 3.4 requires the raw `R || S` concatenation. Every ECDSA token the old
stack minted was therefore rejected by any spec-compliant verifier, and it
accepted only its own.

This fork emits the compliant form, deliberately. Consequences:

* `ES*` tokens minted by the old stack will **not** verify here.
* `ES*` tokens minted here will **not** verify under a jose-based peer.
* `ES*` deployments have to upgrade both ends and re-issue tokens.
* `RS*`, `PS*` and the `RS256` default are unaffected; RS256 signatures from
  either stack verify under the other.

This is pinned by `TestParityECDSAEncoding`, which fails if either the
divergence disappears from the fixtures or this implementation drifts back to
the non-compliant encoding.

## Getting started

### Generating key pairs

Use OpenSSL from the command line to generate the key pairs.

```shell
    openssl genrsa -out private-key.pem 2048
    openssl rsa -in private-key.pem -pubout > public-key.pem
```

### Generate a token for an outgoing request

#### Static keypair

```go
privateKey, _ := asap.NewPrivateKey([]byte(os.Getenv("ASAP_PRIVATE_KEY")))
p := asap.NewMicrosProvisioner([]string{"target_service1", "target_service2"}, time.Minute)
token, _ := p.Provision()
headerValue, _ := token.Serialize(privateKey)
bearer := fmt.Sprintf("Bearer %s", string(headerValue))
```

#### Dynamic autorotating keypair

The cacheTTL must be between 1 second and 2 hours (inclusive).

Also, there are two options for what to pass in for the role:
* Role - your service will assume the role
* Empty string - your service will continue using its existing role

```go
provider, _ := asap.NewSecretsManagerKeypairProvider(privateKeyARN, region, role, cacheTTL)
provisioner := asap.NewDynamicKeyIDProvisioner(ttl, issuer, audience, asap.SigningMethodRS256, provider)

token, _ := provisioner.Provision()
keyID, _ := asap.GetKeyIDFromToken(token)
privateKey, _ := provider.Fetch(keyID)
headerValue, _ := token.Serialize(privateKey)
bearer := fmt.Sprintf("Bearer %s", string(headerValue))
```

### Validate incoming requests

To validate a token you need two things: a way of fetching public keys for
signature verification and a set of validation rules to apply. Every service
should define its own custom validation rules and combine them with the
`DefaultValidator`, which enforces the minimum ASAP requirements.

```go
v := asap.NewValidatorChain(
  asap.DefaultValidator,
  asap.NewSignatureValidator(asap.NewHTTPKeyFetcher(os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"), http.DefaultClient)),
  asap.NewAllowedAudienceValidator("myserviceid"),
)
token, _ := asap.ParseToken(valueFromAuthorizationHeader)
err := v.Validate(token)
if err != nil {
  // Invalid token
}
```

If using an http mux that supports middleware you can add your validation rules
to all incoming requests via:

```go
v := asap.NewValidatorChain(
  asap.DefaultValidator,
  asap.NewSignatureValidator(asap.NewHTTPKeyFetcher(os.Getenv("ASAP_PUBLIC_KEY_REPOSITORY_URL"), http.DefaultClient)),
  asap.NewAllowedAudienceValidator("myserviceid"),
)

m := asap.NewMiddleware(v, nil) // func(http.Handler) http.Handler
```

## Testing

```shell
    make test          # lint + go test -race -cover ./...
    make unittest      # go test -race -cover ./...
    make lint          # go fix -diff + golangci-lint
```

The suite runs on Go 1.26 and Go 1.27.

`testdata/parity/` is the frozen behavioural oracle: 54 wire cases (parse
verdict, protected header, canonical claims for every supported algorithm plus
malformed and adversarial inputs) and 20 validation cases (the verdict of the
real `DefaultValidator` and `SignatureValidator`, anchored at a fixed instant so
the clock can be injected). `testdata/baseline/` keeps the pre-migration green
run and the Go 1.27 init panic for contrast.

Both trees are produced by `tools/paritygen`, a separate module pinned to jose:

```shell
    cd tools/paritygen
    GOTOOLCHAIN=go1.26.0 go run . -out ../../testdata/parity
```

jose cannot run on Go 1.27, so this must be run on Go 1.26 and its output
committed. It is not byte-for-byte reproducible: jose randomises ECDSA and
RSA-PSS signatures, and the validation fixtures are anchored at generation time.

`tools/difffuzz` complements the frozen corpus with a differential harness. It
mints the same claim set with both stacks across the whole algorithm matrix and
cross-verifies the resulting token strings, then compares parse verdicts,
protected headers, canonical claims and every validator verdict against an
independent predictor:

```shell
    cd tools/difffuzz
    GOTOOLCHAIN=go1.26.0 go test ./...              # bounded and seeded
    GOTOOLCHAIN=go1.26.0 go run . -n 20000 -seed 1  # soak
```

It also has to run on Go 1.26 because it imports jose to mint the comparison
tokens. Its only expected divergences are the ECDSA encoding above and the
`HS256`/`none` algorithm policy, which it asserts and counts rather than
tolerates.

## License

Apache License 2.0. Copyright 2015 Atlassian Pty Ltd; see `LICENSE.txt`. This
fork is distributed under the same licence.
