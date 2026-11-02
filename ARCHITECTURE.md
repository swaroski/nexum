# Nexum Architecture

> Status: **v1alpha1, experimental.** Wire formats and APIs may change before beta.

Nexum is an identity, delegation, authorization and audit layer for AI agents.
It answers one question deterministically, close to the resource being
protected:

> *May this agent, acting through this chain of delegated authority, perform
> this action on this resource, right now?*

It is deliberately **not** an agent framework, an LLM, an IdP, a PKI, a policy
language, or a transport. It sits between those things and reuses their
standards.

## 1. Design principles

1. **Neutral by design.** No model, framework, cloud, protocol or IdP is
   required. They appear only as adapter metadata.
2. **Customer-controlled trust.** Every organization is its own root of trust
   (its *trust domain*) and decides whom it trusts. There is no Nexum CA.
3. **Local enforcement.** The gateway decides with local data only. No call to
   any control plane is on the request path.
4. **Least privilege, short-lived authority.** Grants are scoped by capability,
   resource, audience, value and time; trust domains cap grant lifetime
   (default one hour).
5. **Delegation only attenuates.** `authority(child) ⊆ authority(parent)` for
   every hop, enforced cryptographically and by the verifier.
6. **Deterministic security.** LLMs propose actions; deterministic code
   authorizes them. No model output, prompt or agent message can change
   permissions.
7. **Open standards first.** SPIFFE IDs, JWS/JWT, JWK, RFC 8693 `act`,
   RFC 7800 `cnf`, DPoP-style proofs, MCP and A2A as transports.
8. **Auditable by default.** Every decision produces one hash-chained event.
9. **Fail closed.** Unknown, unverifiable, unavailable or ambiguous → DENY.

## 2. Planes

```text
┌──────────────────────── Control plane (future, optional) ───────────────────────┐
│ fleet inventory · policy distribution · trust/federation mgmt · approvals UI    │
│ audit search · risk · compliance. Never on the request path; never sees payloads│
└────────────────────────────────────────────────────────────────────────────────┘
                 ▲ config / audit export (pull, customer-initiated)
┌──────────────── Enforcement plane (this repository) ──────────────────────────┐
│ nexum gateway: sidecar · reverse proxy · shared gateway · laptop · air-gapped │
│   trust.yaml   policy.yaml   state.db (registry, revocations, approvals)      │
│   audit.db / audit.jsonl                                                       │
└────────────────────────────────────────────────────────────────────────────────┘
```

v1 ships only the enforcement plane. Everything it needs is a local file owned
by the customer. A future control plane would *write* those files (or serve
them over a pull API); it would never be consulted per request, and never
store customer credentials or payloads.

## 3. Request flow

```text
 Agent (any framework / model / cloud)
   │  Nexum-Grant: <root>,<child>,...     (delegation chain, root first)
   │  Nexum-Proof: <PoP JWS over body>    (fresh per request)
   │  body: REST decision request | MCP JSON-RPC | A2A JSON-RPC
   ▼
 ┌─────────────────────────── nexum gateway ───────────────────────────┐
 │ 1 adapter.normalize(message)   → action, resource, value            │
 │ 2 verify chain                 → root key ∈ trust store, every hop   │
 │                                   signed by its parent's holder key, │
 │                                   attenuated, unexpired, audienced,  │
 │                                   unrevoked                          │
 │ 3 verify proof of possession   → leaf key, gateway, grant, body hash,│
 │                                   freshness, single use              │
 │ 4 chain authority              → action ∈ leaf.cap, resource ∈ res,  │
 │                                   value ≤ max_value                  │
 │ 5 trust relationship           → receiving org accepts this action   │
 │                                   from the issuing org               │
 │ 6 policy (PDP trait)           → ALLOW | DENY | REQUIRE_APPROVAL     │
 │ 7 approval                     → create, or consume a matching one   │
 │ 8 audit (hash-chained)         → failure ⇒ DENY                      │
 └──────────────────────────────────────────────────────────────────────┘
   │ ALLOW → forward (MCP/A2A) or 200 (decision API); never forwards Nexum
   │         credentials or Authorization headers upstream
   ▼
 Tool / API / Agent / Resource
```

Every step returns exactly one stable reason code (`NX-xxxx`) on failure.
There is no "warn and continue" path.

## 4. Canonical model (`nexum-core`)

The core performs no I/O and no cryptography. It is the neutrality boundary:
everything protocol- or vendor-specific is translated into these types.

| Type | Meaning |
|---|---|
| `AgentId` | A validated SPIFFE ID, `spiffe://<trust-domain>/<path>`. |
| `TrustDomain` | An organization's root of trust, e.g. `xyz.com`. |
| `Capability` | `inventory.read`, or a pattern `inventory.*` / `*`. |
| `ResourcePattern` | `supplier://abc/sku/123`, or prefix `supplier://abc/*`. |
| `AuthorizationRequest` | subject, actor, organization, action, resource, purpose, verified delegation chain, granted authority, context. |
| `AuthorizationDecision` | outcome, ids, matched policy/rule, reason codes, obligations, expiry. |
| `PolicyResult` | what a PDP returns; the gateway composes it with chain/trust/approval results. |
| `ApprovalRequest` | a first-class, single-use, request-bound approval. |
| `RevocationTarget` | agent, grant, trust domain or key. |
| `AgentDescriptor` | normalized registry entry; translated to A2A Agent Cards. |

`covers(a, b)` ("holding `a` implies holding `b`") is the only operation the
attenuation rules use. It is property-tested for transitivity and for
"attenuated child never exceeds parent".

Extension traits:

```rust
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {          // builtin, OPA, Cedar, Cerbos, SpiceDB...
    async fn evaluate(&self, req: &AuthorizationRequest) -> Result<PolicyResult, BoxError>;
}
pub trait RevocationList: Send + Sync {               // local SQLite today; must not need a network hop
    fn is_revoked(&self, t: &RevocationTarget) -> Result<bool, BoxError>;
}
pub trait AuditLog: Send + Sync { ... }               // JSONL, SQLite; Postgres/Kafka/OTel/SIEM later
pub trait ReplayGuard: Send + Sync { ... }            // in-memory; shared store for HA
pub trait ProtocolAdapter: Send + Sync {              // MCP, A2A; more later
    fn normalize(&self, target: &str, headers: &HeaderMap, msg: &Value) -> Result<Normalized, ReasonCode>;
}
```

Errors from any of these become DENY.

## 5. Identity

Agents are identified by SPIFFE IDs regardless of where they run. Nexum does
not issue workload identities; it consumes them:

* **Today:** an organization vouches for an agent by issuing a root grant whose
  `sub` is the agent's SPIFFE ID and whose `cnf.jwk` is the agent's public key.
  `nexum agents register` can generate development keys.
* **Planned adapters:** SPIRE-issued JWT-SVIDs / X.509-SVIDs as the holder
  proof, OIDC/workload identity federation (Entra, Okta, AWS, GCP, Kubernetes
  service accounts) to authenticate the *issuer* side.

An organization may only vouch for agents inside its own trust domain
(`sub` trust domain must equal `org`); this is checked on every hop.

## 6. Delegation grants

A grant is a compact JWS (`typ: nexum-grant+jwt`, `alg: EdDSA` only):

| Claim | Source | Meaning |
|---|---|---|
| `iss` | RFC 7519 | root: org issuer URI; child: parent's `sub` |
| `sub` | RFC 7519 | holder agent (SPIFFE ID) |
| `act.sub` | RFC 8693 | human/principal the chain acts for (immutable down the chain) |
| `org` | Nexum | issuing trust domain |
| `aud` | RFC 7519 | gateways allowed to accept it (⊆ parent) |
| `cap` / `res` | Nexum | capabilities / resource patterns (⊆ parent's delegatable set / resources) |
| `dcap` | Nexum | capabilities the holder may delegate (⊆ `cap`) |
| `mdd` | Nexum | remaining delegation depth (strictly decreasing) |
| `max_value` | Nexum | value ceiling (may only decrease; cannot be dropped) |
| `purpose` | Nexum | purpose binding (immutable once set) |
| `iat`/`nbf`/`exp` | RFC 7519 | child `exp` ≤ parent `exp` |
| `jti` | RFC 7519 | grant id (revocation handle) |
| `prt` | Nexum | base64url SHA-256 of the parent compact token |
| `cnf.jwk` | RFC 7800 | holder's public key |

Unknown claims and unknown JOSE header parameters are **rejected**, so a
restriction a verifier does not understand is never silently ignored.

Chain verification (`nexum-grant::Verifier::verify_chain`):

1. 1 ≤ length ≤ 8.
2. Root: look up `org` in the trust store, select the key by `kid` *within
   that domain only*, verify, require `iss` = configured issuer, no `prt`,
   lifetime ≤ the domain's `max_grant_ttl_seconds`.
3. Each child: signature by the parent's `cnf` key; `iss` = parent `sub`;
   `prt` = hash(parent token); all attenuation rules above.
4. Every grant: time window (with configurable clock skew), audience contains
   this gateway, not revoked (grant id, subject, signing key, trust domain).

Raw credentials are never forwarded: a parent never hands its own grant and
key to a child; it mints a new, narrower, recipient-bound grant.

### Mapping to standards

The grant is a JWT profile, not a new standard. It is designed to map onto:
OAuth 2.0 Token Exchange (RFC 8693: `act`, `may_act`, audience-restricted
exchange — a future token-exchange endpoint can mint root grants from an
enterprise IdP token), RFC 7800 proof-of-possession, RFC 9449 DPoP (the
request proof follows the same idea, bound to the body rather than to
`htm`/`htu`), and SPIFFE (IDs today; SVIDs as holder keys later). If an
interoperable agent-delegation token standard matures, it is intended to
become an alternative grant format behind the same verifier output
(`VerifiedChain`).

## 7. Proof of possession

Grants are not bearer tokens. Each request carries a proof (`typ:
nexum-proof+jwt`) signed by the leaf holder key with claims `jti`, `iat`,
`aud` (this gateway), `gh` (hash of leaf grant) and `bh` (SHA-256 of the
exact request body). The gateway checks all bindings, freshness (default
60 s + skew), and single use (`gh:jti` replay cache). Consequences:

* a stolen grant is useless without the holder's private key;
* a captured request cannot be replayed or re-targeted to another gateway;
* an intermediary cannot change the body (e.g. swap the MCP tool name or the
  amount) without invalidating the proof.

## 8. Trust store and cross-organization trust

`trust.yaml` is the receiving organization's statement of whom it trusts:

```yaml
apiVersion: nexum.dev/v1alpha1
trust_domains:
  xyz.com:
    issuer: https://identity.xyz.com
    keys: [ { kty: OKP, crv: Ed25519, x: "...", kid: "xyz-2026-11" } ]   # JWKS
    allow: [inventory.read, pricing.read, quote.create]
    deny:  [payment.execute, customer.export]
    max_grant_ttl_seconds: 3600
```

Organization ABC verifies XYZ's authority cryptographically with XYZ's
published key, then applies **its own** allow/deny list and **its own**
policy. Nobody — including a future Nexum SaaS — sits in the trust path.
Static JWKS today; `jwks_uri` discovery with pinning and caching is planned.

## 9. Policy

The built-in engine (`nexum-policy`) is intentionally small: subjects, action
and resource patterns, `max_value` / `value_above` / `purpose` conditions,
and delegation rules (`allowed`, `forbidden`, `max_depth`). Combining is
deny-overrides (DENY > REQUIRE_APPROVAL > ALLOW) and the default is DENY. A
condition on `value` never matches a request without a value. Unknown fields
fail validation. External engines implement `PolicyDecisionPoint`.

Policy is evaluated **after** chain authority and trust, so policy can only
narrow what the chain and the trust relationship already permit.

## 10. Approvals

`REQUIRE_APPROVAL` creates an `ApprovalRequest` bound by fingerprint to
(subject, actor, organization, action, resource, value) and returns its id as
an obligation. After a human approves (`nexum approvals approve`), the agent
retries the identical request with `Nexum-Approval: <id>` and a fresh proof.
The gateway re-runs every check, and atomically consumes the approval (single
use). Policy denial still overrides an approval.

## 11. Audit

One event per decision, in JSONL or SQLite, hash-chained:
`event[n].previous_event_hash = event[n-1].event_hash`. Events carry ids,
decisions, reason codes, grant ids and policy ids — never tokens, proofs, keys
or request payloads. `nexum audit verify` detects modification, deletion and
reordering. If the audit write fails, the decision becomes DENY.

## 12. Protocol adapters

| Adapter | Endpoint | Action mapping |
|---|---|---|
| REST decision API | `POST /v1/authorize` | explicit `action`, `resource`, `value` |
| MCP (2026-07-28, Streamable HTTP) | `POST /mcp/{server}` | `tools/call` → configured action or `mcp.<server>.tool.<name>`; other methods → `mcp.<server>.rpc.<method>` |
| A2A v1.0 JSON-RPC (v0.3 aliases) | `POST /a2a/{agent}` | `SendMessage` → `a2a.<agent>.message.send`, etc. |

Adapters only describe a message; they never decide. **Every** message is
authorized, including listing/discovery. JSON-RPC batches and bodies with
duplicate object keys are rejected (the gateway forwards the original bytes,
so it and the upstream must never read them differently). MCP
routing headers (`Mcp-Method`, `Mcp-Name`) must agree with the body. Only
`content-type`, `accept`, `mcp-*` and `a2a-*` headers are forwarded upstream.

Nexum does not reimplement MCP or A2A. The gateway works at the JSON-RPC
message layer, which is all enforcement needs, so it does not depend on an
MCP or A2A SDK. Agent discovery uses A2A Agent Cards (`nexum agents inspect
--a2a-card`) rather than a competing format.

## 13. Neutrality test

> A LangGraph agent on AWS using a hosted LLM, talking A2A to a Mastra agent on
> Azure, which calls an MCP tool.

The core sees: two SPIFFE IDs, two trust domains, a grant chain, an action, a
resource, a policy and some context. "LangGraph", "AWS", the model vendor, "A2A",
"Mastra", "Azure" and "MCP" appear at most as `context.protocol` and
`context.attributes`, which the built-in policy engine does not even read.

## 14. Crates

| Crate | Responsibility | Depends on |
|---|---|---|
| `nexum-core` | model, patterns, reason codes, extension traits | serde, chrono, uuid |
| `nexum-grant` | JWS (EdDSA only), keys/JWK, grants, proofs, chain verification, trust store, replay guard | core, ed25519-dalek, sha2 |
| `nexum-policy` | built-in PDP | core, yaml_serde |
| `nexum-audit` | hash-chained JSONL and SQLite sinks | core, rusqlite |
| `nexum-gateway` | config, local state, pipeline, axum server, MCP/A2A adapters | all of the above, axum, reqwest (rustls) |
| `nexum` (cli) | `nexum` binary | gateway |

All crates are `#![forbid(unsafe_code)]`.

## 15. Key custody

Development keys are Ed25519 private JWK files written with `0600`
permissions. Signing is isolated behind `KeyPair`; production deployments
should replace it with a signer backed by a KMS/HSM (AWS KMS, Azure Key
Vault, GCP KMS, HashiCorp Vault Transit, PKCS#11). Ed25519 is supported by
all of these. Key rotation is publishing a second key (new `kid`) in the
trust domain's JWKS, issuing with it, then removing or revoking the old one.

## 16. Deliberately deferred

* Hosted control plane, UI, multi-tenancy, billing, marketplace.
* Dynamic federation (`jwks_uri`, signed trust bundles, SPIFFE federation).
* External PDP adapters (OPA, Cedar, Cerbos, SpiceDB).
* Native TLS listener (terminate TLS in front of the gateway today).
* Shared replay cache and state for multi-instance gateways.
* Generic HTTP reverse-proxy mode with route → action mapping.
* Token exchange endpoint (RFC 8693) for minting root grants from IdP tokens.
* Policy simulation ("what changes if I deploy this policy?") — the audit log
  already records every input needed to replay decisions.
* OpenTelemetry export (metrics are Prometheus text today; logs are `tracing`).
