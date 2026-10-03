# Migration report: `SermoDigital/jose` → `golang-jwt/jwt/v5`

Status: **complete**. Date: 2026-10-03.
Commits: `5b4e8c8` … `81db89f` (7 commits on top of upstream `97f05bd`).

This is an experimental fork; the report describes work done on it, not a
production-ready release. See the disclaimer in `README.md`.

---

## 1. Motivation and root cause

Upstream `go-asap` v2 depended on
`github.com/SermoDigital/jose@v0.9.2-0.20161205224733-f6df55f235c2`, unmaintained
since 2016. The module **compiles** on Go 1.27 but every test binary and every
program that links it dies at package initialisation:

```
panic: crypto: RegisterHash of unknown hash function

goroutine 1 [running]:
crypto.RegisterHash(...)
	/opt/homebrew/Cellar/go/1.27.1/libexec/src/crypto/crypto.go:158
github.com/SermoDigital/jose/crypto.init.0()
	.../jose@v0.9.2-.../crypto/none.go:11 +0x30
```

Root cause, `jose/crypto/none.go:11`:

```go
func init() {
	crypto.RegisterHash(crypto.Hash(0), h)
}
```

`crypto.Hash(0)` is not a valid hash identifier, and Go 1.27 made
`crypto.RegisterHash` reject it. Nothing in application code can work around an
`init` panic, so the dependency had to go. `go build` succeeding while every
binary fails at startup is worth calling out: the failure is invisible to a
build-only check.

Verified baseline before any change (`testdata/baseline/`):

| Go | Result |
| --- | --- |
| 1.26.0 | green — main package 79.6% coverage, `internal/keyrefresh` 97.8% |
| 1.27.1 | `FAIL` with the panic above |

## 2. Scope and result

* jose replaced with `github.com/golang-jwt/jwt/v5` **v5.3.1**.
* The legacy v1 root module (`bitbucket.org/atlassian/go-asap`) was deleted; it
  was superseded, duplicated the v2 sources, and was equally unusable on 1.27.
* The v2 module was promoted to the repository root as
  `github.com/mickstar/go-asap`: no `/v2` suffix, no stray directory, README and
  CI at the top level.
* Go directive kept at `go 1.26.0`; the suite runs on **1.26 and 1.27**.
* Since the public API exposed jose types (`jwt.JWT`, `jws.JWS`,
  `crypto.SigningMethod`), an **ASAP-owned compatibility layer** replaces them
  rather than leaking another JWT library's types.

Result: `go test -race ./...` green on 1.27 and 1.26, `golangci-lint` clean,
`go fix -diff` clean, no jose in the shipped module's `go.mod`, `go.sum` or
module graph.

## 3. Method: freeze the old behaviour before touching it

The difficult part of this migration is not the code, it is the *evidence*.
jose cannot execute on Go 1.27, so the old implementation cannot run on the
shipping toolchain: parity either has to be captured as data in advance, or
compared inside a Go 1.26 sandbox. This work does both — the frozen corpus
described here, and the differential harness in `tools/difffuzz`.

So the old behaviour was **materialised as data first**. `tools/paritygen` is a
separate module, run with `GOTOOLCHAIN=go1.26.0`, that links the **pre-migration**
library — the jose-based tree extracted from commit `97f05bd` by
`make parity-oracle`, *not* the port — and records what it does into
`testdata/parity/`:

| File | Contents |
| --- | --- |
| `keys.json` | fixed RSA-2048, EC P-256/P-384/P-521 key material in PEM |
| `wire.json` | 54 tokens plus jose's exact parse verdict, decoded protected header and canonical claim map |
| `validation.json` | 20 tokens plus the verdict of the **pre-migration** `DefaultValidator`, `SignatureValidator`, `AllowedAudienceValidator` and `AllowedClaimValuesValidator` |
| `meta.json` | generator path, **which library and commit the verdicts came from**, jose version, toolchain, and the `anchor` instant |

Three details make the corpus usable as a lasting oracle:

* **The generator must link the old library, not the port.** This is the point
  that is easy to get wrong, and an earlier revision of this work got it wrong:
  the generator was pointed at the migrated module, which made every `asap*`
  verdict a recording of the library under test and left `TestParityValidation`
  structurally unable to detect a mis-port. The evidence was embarrassingly
  concrete — the committed fixture stored golang-jwt's
  `"token signature is invalid: key is of invalid type: RSA verify expects *rsa.PublicKey"`
  beside jose's `"key is invalid"` for the same token, i.e. post-migration text in
  a field the report called jose-era. `meta.json` now names the oracle library and
  commit, and the CI `parity fixtures` job re-extracts that tree, regenerates, and
  asserts the committed verdicts reproduce from it.
* **Validation is anchored to a fixed clock.** Time-dependent verdicts are only
  reproducible if "now" is fixed, so `validation.json` records the instant the
  fixtures were generated and the test replays them through an injectable clock
  (`nowFn`, an `atomic.Value` so the swap is race-free alongside the package's
  parallel tests).
* **The generator is not byte-for-byte reproducible, and says so.** jose
  randomises ECDSA and RSA-PSS signatures, so every `ES*`/`PS*` token changes on
  each run, and the validation fixtures move with the anchor. The committed
  corpus is treated as frozen; the *verdicts* it records are stable and are what
  CI reproduces.

The corpus covers: `RS`/`PS`/`ES` 256/384/512, `HS256`, `none`, single/multiple/
absent/`null` audiences, `kid` variants (missing, empty, non-string, traversal,
dot segments, invalid characters, unicode, 4096 bytes, wrong issuer prefix),
required-claim absence, lifetime boundaries (exactly one hour, one second over,
one second under), expiry, not-yet-valid, unsupported algorithms, a wrong-key
signature, a tampered payload, base64 padding, whitespace, wrong segment counts,
non-JSON and non-object payloads, and duplicate JSON keys.

## 4. Compatibility layer

jose types are gone from the public API. The substitutions are mechanical for a
caller:

| Before (`bitbucket.org/atlassian/go-asap/v2`) | After |
| --- | --- |
| `jwt.JWT` (token interface) | `asap.Token` |
| `jwt.Claims` / `jws.Claims` | `asap.Claims` |
| `jwt.Validator{EXP, NBF}` | `asap.ValidationOptions{EXP, NBF}` |
| `crypto.SigningMethod` | `asap.SigningMethod` (concrete) |
| `crypto.SigningMethodRS256` … | `asap.SigningMethodRS256` … |
| `crypto.Unsecured` | no equivalent — ASAP has no signing method for `none` |
| `token.(jws.JWS).Protected().Get(k)` | `token.Protected().Get(k)` |
| `jwt.ErrTokenIsExpired` | `asap.ErrTokenIsExpired` |

Notes on the shape of the layer:

* `asap.Claims` stays a plain `map[string]any`, as jose's was, and keeps the same
  accessors including `Remove*`. It additionally satisfies the golang-jwt claims
  interface so it can be handed to the parser directly.
* `asap.ValidationOptions` is not named `Validator` because the package already
  exported a `Validator` **interface** for validating tokens.
* `asap.Token` gained `Protected()`, so the header is reachable without a type
  assertion. That removes the `"Token is not a JSON web signature"` branch from
  `GetKeyIDFromToken`: it is unreachable, not deleted for convenience.
* Parsed tokens keep the serialized form as their cache key; freshly minted
  tokens do not implement `CacheableKeyer` at all, matching the old type
  behaviour (a jose `JWS` returned by `Provision()` never implemented it either).
* `asap.Header` is a plain `map[string]any`. jose's `Protected` additionally
  implemented `json.Marshaler`/`json.Unmarshaler` — marshalling to a base64
  string and unmarshalling by decoding first — and `Claims` exposed `Base64()`.
  Nothing in this package used either, so neither is reproduced. Code that
  round-tripped a protected header through JSON has to stop doing so; the
  accessors (`Get`/`Set`/`Has`/`Del`) are unchanged.

## 5. Parsing and validation semantics

Both are deliberately re-derived from jose's source rather than taken from
golang-jwt's defaults, because the defaults differ in ways that would reject
tokens the old stack accepted.

**Parsing** (`ParseToken`) does not verify. It uses `ParseUnverified`, which
already reproduces two jose behaviours for free: an algorithm that is not
registered is rejected (`signing method (alg) is unavailable`), and a missing
`alg` is rejected. One case needed explicit work: `encoding/json` resolves the
literal `null` to a nil interface *without* calling `Claims.UnmarshalJSON`, so the
parser cannot distinguish a `null` payload from a claims object. jose asserted
the decoded payload was an object; `ParseToken` decodes the payload segment
through the parser's own `DecodeSegment` and applies the same assertion.

**Validation** does not use golang-jwt's claim validator. Its defaults would
change behaviour in two ways:

* `verifyIssuedAt` is called unconditionally, so a token with an `iat` in the
  future is rejected. jose **never** validates `iat`.
* `verifyExpiresAt` errors when `now >= exp+leeway`; jose errors when
  `now > exp+leeway`. The two disagree at exactly one instant.

So verification runs with `WithoutClaimsValidation()` — which skips *claim*
validation only, never signature verification — and the lifetime rules are
re-implemented verbatim from jose's `Claims.Validate`:

```go
if exp, ok := c.Expiration(); ok {
	if now.After(exp.Add(expLeeway)) {
		return ErrTokenIsExpired
	}
}
if nbf, ok := c.NotBefore(); ok {
	if !now.After(nbf.Add(-nbfLeeway)) {
		return ErrTokenNotYetValid
	}
}
```

Inclusive boundaries, absent `exp`/`nbf` tolerated, and the same error text.

**Signature verification** is pinned to the caller's algorithm with
`WithValidMethods([]string{method.Alg()})`, and the method itself comes from the
ASAP allow-list (`signingMethodMap`), so a token cannot talk the verifier into a
weaker algorithm. `none` is not in the allow-list and is not reachable as a
signing method.

## 6. Wire-format fidelity

| Aspect | Behaviour |
| --- | --- |
| Protected header | `{"alg": …, "kid": …, "typ": "JWT"}`, `typ` absent when the source token omitted it |
| Times | integer epoch seconds (`exp`, `iat`, `nbf`) |
| Claim numbers after parsing | `float64`, as jose produced |
| `aud`, one audience | bare JSON string |
| `aud`, two or more | JSON array |
| `aud`, none supplied | `"aud": null` (key present) — verified against jose, not assumed |
| `kid` | in the protected header, never the payload |

## 7. Divergences

### 7.1 Intentional: ECDSA signatures are not interoperable with the old stack

The oracle surfaced a genuine defect in jose v0.9.2. For `ES256`, `ES384` and
`ES512` it signed with ASN.1/DER:

```go
// jose/crypto/ecdsa.go:90
signature, err := asn1.Marshal(ECPoint{R: r, S: s})
```

RFC 7518 §3.4 requires the raw `R ‖ S` concatenation. Measured from the frozen
corpus, the `ES*` signature segments are DER `SEQUENCE`s:

| Algorithm | jose signature | RFC 7518 expects |
| --- | --- | --- |
| ES256 | 71 bytes, starts `0x30 0x45` | 64 bytes |
| ES384 | 104 bytes, starts `0x30 0x66` | 96 bytes |
| ES512 | 138 bytes, starts `0x30 0x81` | 132 bytes |

DER lengths vary by a byte or two depending on integer encoding, which is itself
a signature of the defect. Every ECDSA token the old stack minted was therefore
rejected by any spec-compliant verifier; it only ever verified itself.

**This port does not reproduce the defect.** It emits the compliant form, which
means:

* `ES*` tokens minted by the old stack do not verify here.
* `ES*` tokens minted here do not verify under a jose-based peer.
* `ES*` deployments must upgrade both ends and re-issue tokens.
* `RS*`, `PS*` and the `RS256` default are unaffected and verify in both
  directions.

This is pinned by `TestParityECDSAEncoding`, which asserts that jose's
signatures still carry the DER tag (so the evidence has not been lost), that they
are rejected, and that this implementation's signatures are exactly `2 ×` the
curve half-width.

### 7.2 Accepted: library error text differs for signature and time failures

Accept/reject decisions match everywhere; the *text* of errors raised inside the
JWT library does not, and matching it would be misleading. Errors raised by this
package's own validators (kid rules, algorithm allow-list, required claims,
lifetime) are byte-identical, and the parity test enforces exactly that split:
exact match for package-owned messages, verdict-only for library-owned ones.

### 7.3 Relaxation: the algorithm registry is a superset

golang-jwt knows more algorithms than jose did (EdDSA, for instance). Such a
token now parses instead of failing at parse time. It is still rejected by the
allow-list during validation, so no weaker algorithm becomes acceptable.

### 7.4 Fixed during the migration, so no longer divergent

Array audiences, `null` payloads, `Header.Has` and the cache-key collision — see
below. These were regressions introduced by the port and closed before the
module was published.

### 7.5 Deliberate: the expiration message no longer depends on the host time zone

`ExpirationValidator` reports the two claim timestamps it compared. Claim times
are read back through `time.Unix`, which carries the **host's** zone, so the
message used to read differently on different machines for the same token:

```
machine at +1000:  IssuedAt time 2026-10-03 18:34:50 +1000 AEST is more than an hour before …
UTC runner:        IssuedAt time 2026-10-03 08:34:50 +0000 UTC is more than an hour before …
```

That is a defect rather than a feature: the text is not comparable across logs,
and it made the frozen corpus non-portable. The first CI run of this repository
caught it precisely that way — the fixture recorded the generator's `AEST`
rendering and the ubuntu runner produced `UTC`, failing `TestParityValidation`.

The message is now rendered in UTC, so it depends only on the instant. This is a
textual change from the jose era; the instant reported, the wording and the
accept/reject decision are unchanged. `TestExpirationMessageIgnoresHostZone`
pins it by asserting that the same instant, expressed in two different zones,
renders identically, and the suite is exercised under several `TZ` values.

### 7.6 Two further differences, documented rather than fixed

* **`Token.Validate` checks the signed bytes, not later in-memory mutations.**
  Verification re-parses the token's own compact form, so a caller that mutates
  `token.Claims()` after `ParseToken` and before `Validate` no longer influences
  the lifetime check; jose validated the live payload, so it did. The new
  behaviour is the safer one — it validates exactly what was signed — and no ASAP
  code path mutates claims to decorate a token, but it is a divergence from
  "preserve the old behaviour" and is recorded here rather than left implicit.
* **`Claims.GetTime` range-checks the unsigned conversions.** The `uint` and
  `uint64` arms report the claim as absent for values above `math.MaxInt64` where
  jose wrapped them to a negative timestamp. For an in-memory `exp` this is the
  *permissive* direction: jose's wrapped timestamp looked expired, while an absent
  claim skips the check. It is unreachable from the wire — JSON numbers decode to
  `float64` and `SetTime` stores `int64` — and it exists only to satisfy `gosec`'s
  overflow check, but it is semantic drift and is listed here for completeness.
  Restoring jose's exact wrapping would require a suppression in the lint gate
  for a path nothing can reach; that trade was not taken.

## 8. Defects found during the migration

| # | Defect | Impact | Guard |
| --- | --- | --- | --- |
| 1 | `Claims.Audience` called `stringify(t)` instead of `stringify(t...)`, so a JSON array audience produced *no* audiences | `NewAllowedAudienceValidator` rejected multi-audience tokens; a consumer treating an empty audience list as "no restriction" could be bypassed | `TestClaimsAudienceNormalisation`, `TestAudienceValidatorArrayClaim`, and the `AudienceOK` verdict in `validation.json` |
| 2 | Minted tokens satisfied `CacheableKeyer` with an empty key, because parsed and minted tokens shared one type | Two minted tokens collide in the caching validator, which can then serve an unvalidated token | `TestProvisionedTokensAreNotCacheable` |
| 3 | `null` payload accepted and yielded empty claims that passed the lifetime check | `ParseToken` accepted what jose rejected; `SignatureValidator` alone would have accepted such a token | `TestNonObjectPayloadIsRejected` |
| 4 | `Header` lost the `Has` accessor | Source-compatibility break for `token.Protected().Has(…)` | `TestHeaderHas` |
| 5 | jose emitted DER ECDSA signatures (upstream defect, not introduced here) | Every `ES*` token the old stack minted was rejected by compliant peers | `TestParityECDSAEncoding` |
| 6 | `ExpirationValidator` rendered claim timestamps in the host's time zone, so its message differed by machine | Log text is not comparable across hosts; the frozen corpus was not portable, and the first CI run failed on a UTC runner while passing locally | `TestExpirationMessageIgnoresHostZone`, plus running the suite under several `TZ` values |
| 7 | The fixture generator was pointed at the **migrated** module, so every `asap*` verdict it recorded was a recording of the library under test | `TestParityValidation` could not detect a mis-port; the corpus was a self-portrait of the code it was supposed to check | Generator rewired to the pre-migration tree (`make parity-oracle`), `meta.json` records the oracle library and commit, and the CI `parity fixtures` job re-extracts it and asserts the committed verdicts reproduce |
| 8 | `WithValidMethods` — the control that pins verification to the caller's algorithm — had no test | Deleting that one line left the whole suite green, and accepted an HS256 algorithm-confusion forgery when the key is passed as raw bytes | `TestValidateRejectsAlgorithmSubstitution`; verified by mutation — the test fails on the un-pinned build and the forgery succeeds there |
| 9 | The inclusive `exp`/`nbf` leeway boundary that `validateTime` exists to preserve had no test | Shifting either comparison by one instant left the suite green; the nearest fixtures sit minutes from the boundary | `TestLeewayBoundaryIsInclusive`; verified by mutation |

Defects 1–4 were found by independent review of the diff against the frozen
behaviour, not by the implementation itself; defect 6 was found by the first CI
run on a UTC runner; defects 7–9 were found by a second, adversarial review that
began by trying to falsify the parity claim rather than restating it. Defect 1
was additionally invisible to the first version of the corpus: the fixtures
replayed `DefaultValidator` and `SignatureValidator`, neither of which reads
`Claims.Audience()`. The corpus was extended to record
`NewAllowedAudienceValidator` and `NewAllowedClaimValuesValidator` verdicts so
that this class of bug is covered by the oracle and not only by a hand-written
test.

Defects 7–9 share a lesson worth stating: a test that passes is not evidence
until you have seen it fail. Each of the three was confirmed by mutating the
control out of the tree and watching the suite stay green — which is the only
way to distinguish a guard from a coincidence.

## 9. Verification evidence

| Check | Command | Result |
| --- | --- | --- |
| Build | `go build ./...` | ok on 1.26 and 1.27 |
| Race suite | `go test -race ./...` | green, 1.27 |
| Go floor | `GOTOOLCHAIN=go1.26.0 go test ./...` | green |
| Coverage | `go test -cover ./...` | 80.0% main, 97.9% `internal/keyrefresh` (baseline 79.6% / 97.8%) |
| Lint | `make lint` | `go fix -diff` clean, golangci-lint v2.14: 0 issues |
| Dependencies | `go mod graph \| grep -i sermo` | empty; jose absent from `go.mod` and `go.sum` |
| Oracle replay | `go test -run TestParity ./...` | 54 wire + 20 validation cases |
| Differential fuzz | `make difffuzz` | 0 unexpected divergences |
| Fresh clone | `git clone . /tmp/x && go test -race ./...` | green, no `replace` in `go.mod` |
| README examples | compiled against the module in a scratch module | build and vet clean |
| Time-zone portability | `TZ=<zone> go test -count=1 ./...` for UTC, Australia/Sydney, America/New_York, Asia/Kolkata | green in all four |
| Oracle provenance | `make parity-oracle && make parity-fixtures`, then compare the recorded verdicts | the committed 20 verdict sets reproduce from the pre-migration library |
| Algorithm pinning | `TestValidateRejectsAlgorithmSubstitution` | passes at HEAD, fails when `WithValidMethods` is deleted (the forgery then verifies) |
| Leeway boundary | `TestLeewayBoundaryIsInclusive` | passes at HEAD, fails when either comparison is shifted by one instant |
| CI | `.github/workflows/ci.yml` on GitHub runners | `test` (Go 1.26.x and 1.27.x), `lint` (golangci-lint v2), `parity fixtures`, `differential fuzz` |

Test corpus: 92 test functions in the main package plus 20 in
`internal/keyrefresh`.

**Differential harness.** `tools/difffuzz` is a second jose-pinned module that
mints the same claim specification with both stacks and feeds every token string
to both, comparing parse verdicts, canonical protected headers, canonical claims,
and the `DefaultValidator`, `SignatureValidator` and raw-signature verdicts. The
committed bounded test runs 3,000 iterations / 6,000 tokens; soak runs of 20,000
iterations and roughly 96,000 further iterations across additional seeds all
reported **0 unexpected cross-library verdict mismatches and 0 unexpected
divergences**. Expected divergences (the ECDSA encoding, and `HS256`/`none`
policy) are asserted and counted rather than tolerated.

Its independence is uneven, and the report above should not imply otherwise: it
is genuinely independent of this package where it compares against jose — wire
behaviour (parse verdict, decoded header and claims) and crypto (raw signature
verification) — but for ASAP-specific *policy* the "independent predictor" is a
transcription of this package's own validators, so the two can agree while both
are wrong. It catches transcription slips, not a shared misreading. Against that
limit, the frozen corpus is the primary evidence and the harness is the
corroborating sweep.

**The corpus was mutation-tested.** Reintroducing defect 1 made
`TestParityValidation/valid_multi_aud` fail against the jose-derived verdict, so
the fixture genuinely constrains the claim-shape path instead of restating it.
The same check is guarded permanently: the generator refuses to emit a fixture
set whose audience verdicts do not discriminate, and
`TestParityFixtureCoverage` asserts the same on the committed file.

## 10. Reproducing

```shell
# shipped module
go build ./...
go test -race ./...
GOTOOLCHAIN=go1.26.0 go test ./...
make lint

# differential harness (separate module, needs Go 1.26 because it imports jose)
make difffuzz

# regenerate the frozen oracle (only when its content must change deliberately)
make parity-fixtures
```

## 11. Residual risk and limits

* **`ES*` interoperability is broken in both directions by design** (7.1). This
  is the one change that requires coordinated action by users of the old stack.
* **Message parity is deliberately not preserved** for errors raised inside the
  JWT library (7.2), and two package-owned details changed on purpose: the
  expiration message no longer depends on the host's time zone (7.5), and two
  further differences are recorded in (7.6). If a caller matches on any of them,
  it must be updated.
* **The frozen corpus only knows what its generator recorded.** It cannot detect
  a mis-port in behaviour it never exercised, which is precisely how defect 1
  escaped it. `tools/difffuzz` widens the net, with the caveat in §9 that its
  policy predictors are transcriptions rather than an independent oracle.
* **A passing suite is not evidence until it has been seen to fail.** Three of
  the defects listed in §8 were found by mutating a control out of the tree and
  observing that nothing noticed.
* **Both oracles share one blind spot:** they are limited by the claim, header and
  algorithm shapes they generate. They are a strong regression net, not a proof.
* **`tools/paritygen` and `tools/difffuzz` depend on jose and therefore on Go
  ≤ 1.26.** They are excluded from the shipped module, CI-gated separately, and
  exist only to reproduce and extend the evidence above.
* No independent third-party security audit has been performed. The verification
  here is internal, however mechanical.

## 12. References

* jose `none.go` `init` panic — `crypto.RegisterHash(crypto.Hash(0), h)`.
* RFC 7518 §3.4 — ECDSA signatures are `R ‖ S`, not DER.
* RFC 7519 §4.1 — registered claim semantics.
* `github.com/golang-jwt/jwt/v5` v5.3.1 — `ParseUnverified`,
  `WithoutClaimsValidation`, `WithValidMethods`, `WithLeeway`.
* ASAP specification — <https://s2sauth.bitbucket.io/>
