# Security policy

## This fork is an experiment

`go-asap` here is a personal fork of Atlassian's internal ASAP library, ported off
the unmaintained `SermoDigital/jose` dependency. **It is not for production use.**
Read `README.md` and `MIGRATION.md` before relying on any of it.

There is no support commitment, no security response SLA, and no bug bounty.
Reports are handled on a best-effort basis by one person, and a report may go
unfixed indefinitely. If you need an ASAP implementation in production, use a
maintained library and have your own security team review it.

## Reporting a vulnerability

Report privately through GitHub: **Security → Advisories → Report a vulnerability**
(<https://github.com/mickstar/go-asap/security/advisories/new>).

Please do not open a public issue for a suspected vulnerability.

A useful report contains:

- the commit SHA you tested against
- your Go toolchain (`go version`) and `TZ`
- a minimal reproduction: the token string, or a short Go snippet against this
  module
- what you expected and what actually happened

Tokens are credentials. Redact the signature and any real key material, and never
paste a live ASAP token into a report — a token with synthetic keys and the same
shape is enough to demonstrate a defect.

## Supported versions

Only `main` is supported. There are no tagged releases and no backports.

## Scope

### In scope

- Anything in the shipped module that makes verification weaker than it should
  be: accepting a token it should reject, skipping a signature or lifetime check,
  algorithm confusion, or `kid` handling that escapes its issuer.
- Divergences from the pre-migration behaviour that are **not** documented as
  intentional in `MIGRATION.md` §7. Behavioural parity is the acceptance bar for
  this fork, so an undocumented divergence is a finding.
- The test tooling in `tools/` and the frozen fixtures in `testdata/parity/`,
  including any way they could pass while the library is wrong. A test that
  cannot fail is treated as a defect here, not a nitpick.

### Already known and intentional — will be closed as duplicates

All documented in `MIGRATION.md` §7:

- **`ES256`/`ES384`/`ES512` tokens minted by the pre-migration stack do not verify
  here, and vice versa.** jose v0.9.2 emitted ASN.1/DER ECDSA signatures where RFC
  7518 §3.4 requires the raw `R ‖ S` concatenation; this fork emits the compliant
  form. `RS*`, `PS*` and the `RS256` default are unaffected and interoperate in
  both directions.
- Error **text** raised inside the JWT library differs from jose's. Accept/reject
  decisions do not.
- The expiration validator's message renders claim instants in UTC rather than
  the host's time zone.
- `Claims.GetTime` range-checks unsigned conversions where jose wrapped them to a
  negative timestamp.

### Out of scope

- The retired `SermoDigital/jose` dependency. The shipped module does not use it;
  only the test tooling in `tools/` links it. It is unmaintained upstream, and
  reports about jose itself belong with that project.
- The ASAP protocol or its specification, and Atlassian's own implementation.
  <https://s2sauth.bitbucket.io/>
- General hardening asks that are not defects in this code — the absence of a
  fuzzing campaign, a formal audit, or an external review.

## What is already verified

`README.md` and `MIGRATION.md` §9 list the gates: parity replay against a frozen
corpus recorded from the pre-migration library, a differential harness that mints
and verifies with both stacks, mutation-verified pins on the algorithm allow-list
and on the `exp`/`nbf` leeway boundary, and CI on Go 1.26 and 1.27.

If you believe one of those gates is illusory — that the suite would stay green
with a control removed — that is a finding worth reporting. There are three
precedents in `MIGRATION.md` §8.
