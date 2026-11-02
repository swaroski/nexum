---
title: Security overview
description: What Nexum protects, how, what it hasn't proven yet, and how to report issues.
---

:::caution[Status]
Nexum is **alpha** (`nexum.dev/v1alpha1`). It has **not** completed an
independent security review. Don't rely on it as the only safeguard for
high-impact actions. Reviews will be published here as they happen.
:::

## What the runtime guarantees, by design

| Property | Mechanism |
|---|---|
| Authority traces back to a trusted organization | root grants verified against the receiver's trust store; keys looked up within the claimed domain only |
| Delegation only narrows | attenuation checked on every hop of every request; property-tested |
| Stolen grants are useless | holder-of-key grants plus a fresh, single-use proof over the exact body |
| Receivers stay in control | per-partner allow/deny and the receiver's own policy, applied after the chain |
| Fail closed | anything unknown, unverifiable or unavailable is DENY with a stable [reason code](/nexum/reference/reason-codes/) |
| Nothing unaudited | the decision becomes DENY if its hash-chained audit event can't be written |

Cryptography is **Ed25519 only** (`alg: EdDSA`); `none`, HMAC and RSA are
rejected, as are unknown claims and JOSE header parameters. `unsafe` is
forbidden in every runtime crate. The one exception is the browser
playground's WebAssembly shim
([`nexum-playground/src/wasm.rs`](https://github.com/swaroski/nexum/blob/main/crates/nexum-playground/src/wasm.rs),
about 40 lines for the wasm ABI and the randomness import), which is compiled
only for `wasm32` and never runs server-side.

## How we test it

- Negative tests and property tests for chain verification and attenuation.
- The [official security eval suite](/nexum/guides/evals/): 94 attack and
  boundary scenarios through the real pipeline, on every commit.
- An end-to-end cross-company demo in CI.

## Supply chain

| Control | Status |
|---|---|
| `cargo deny` (licenses, sources, bans) and `cargo audit` (RustSec) in CI | in place |
| Lockfile enforced (`--locked`) in CI and the GitHub Action | in place |
| Signed releases, checksums, SBOM, provenance attestations | planned with the first published release |

## Known limitations

From the [threat model](/nexum/security/threat-model/):

- Replay cache and local state are per instance: run one replica per state
  store until shared state lands.
- No built-in rate limiting or TLS listener: put both in front of the gateway.
- The decision API relies on the caller honoring the decision; the MCP and A2A
  proxies enforce inline. Nexum can't protect a resource that's reachable
  around it.
- Anyone with write access to the gateway's files is an administrator. There
  is no separation of duties for approvals yet.
- Trace ids are caller-asserted and only used for correlation.

## Reporting a vulnerability

Please **don't** open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/swaroski/nexum/security/advisories/new).
We aim to acknowledge within 3 business days. See
[SECURITY.md](https://github.com/swaroski/nexum/blob/main/SECURITY.md) for scope.
