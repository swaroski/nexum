# Nexum Platform Plan

> Status: **proposal**, November 2026. Phases 1–3 (docs site, authority
> tracing, Nexum Eval), the OPA part of phase 5, the local console (6) and A2A
> discovery (part of 7) are implemented in this repository; the rest is
> design only. Major pieces graduate to numbered RFCs before implementation.

Nexum grows from an enforcement runtime into four products built on one trust
model, **without** moving anything into the request path that isn't needed to
answer:

> *May this agent, acting through this chain of delegated authority, perform
> this action on this resource, right now?*

| Product | What | License | Status |
|---|---|---|---|
| **Runtime** | gateway, identity, delegation, trust, policy, approvals, audit, CLI | Apache-2.0 | alpha |
| **Eval** | authorization security scenarios, attack library, CI | Apache-2.0 (runner + official suite) | alpha |
| **Console** | fleet, traces, trust graph, approvals, risk, policy distribution | open-core: local console OSS, hosted/enterprise commercial | design |
| **Hub** | trusted agent directory: private first, federated later | undecided | later |

The Runtime never depends on Console or Hub. A Console outage never means
"authorization unavailable".

## 1. What exists today

| Area | Where | Notes |
|---|---|---|
| Canonical model, reason codes, pipeline stages | `nexum-core` | protocol-, model-, cloud-neutral |
| Grants, attenuation, proofs, trust store | `nexum-grant` | Ed25519 only, holder-of-key |
| Built-in PDP behind `PolicyDecisionPoint` | `nexum-policy` | deny-overrides, default deny |
| Hash-chained audit behind `AuditLog` | `nexum-audit` | SQLite, JSONL |
| Gateway: decision API, MCP/A2A proxies, approvals, revocation, metrics | `nexum-gateway` | fail closed |
| Authority tracing: `nexum.authorize` spans, OTLP export, `traceparent` correlation, `nexum trace inspect` | `nexum-gateway`, `nexum-cli` | Phase 2 |
| Nexum Eval: DSL, sandbox runner, 12 built-in attacks, official suite (`evals/`), GitHub Action (`action.yml`) | `nexum-gateway::eval`, `evals/` | Phase 3 |
| Docs site with generated reason-code, error and CLI reference; wasm playground | `website/`, `nexum-sim`, `nexum-playground` | Phase 1 |
| Administrative audit events, `policies simulate`, eval baselines | `nexum-cli`, `nexum-gateway::simulate` | Phase 3 |
| OPA policy provider | `nexum-gateway::opa` | Phase 5 |
| Local console, `risk scan`, `discover a2a` | `nexum-cli`, `nexum-gateway::{risk,discover}` | Phases 6–7 |

## 2. Abstractions that stay untouched

New products **consume** these. They are not modified to suit a product.

- **`AuthorizationRequest` / `AuthorizationDecision`** and the neutrality
  boundary: identity, actor, organization, trust, delegated authority, action,
  resource, purpose, conditions, policy. Frameworks, clouds and models stay
  opaque metadata.
- **The grant format and `Verifier`**: attenuation rules, holder-of-key proofs,
  replay protection. Alternative grant formats (SVIDs, RFC 8693-minted roots)
  enter *behind* `VerifiedChain`, not beside it.
- **Pipeline order** in `Authorizer::decide`: chain → proof → request →
  authority → trust → policy → approval → audit. `ReasonCode::stage()` and
  `nexum trace inspect` rely on it.
- **`PolicyDecisionPoint`, `AuditLog`, `ProtocolAdapter`, `RevocationList`**
  traits: extension points for OPA/Cedar, SIEM sinks, new protocols.
- **Reason codes**: stable once released, never reused.
- **Local files as source of truth**: `trust.yaml`, `policy.yaml`,
  `state.db`, audit log. A control plane may *write* them; the gateway never
  asks it anything per request.

## 3. Schema changes

Done (backward compatible):

| Change | Why |
|---|---|
| `AuditRecord.{trace_id, chain, value, purpose}`, optional and omitted when empty, so earlier events keep their canonical form and verify | authority traces; policy simulation needs `value` and `purpose` |
| `ReasonCode::stage()`, `nexum_core::Stage` | derive per-check results from one code |
| `ReasonCode::security_event()` | stable alertable event names |
| `EvalSuite` (`nexum.dev/v1alpha1`) | Eval DSL, section 6 |

| `AuditRecord.{operator, detail}` and administrative `event_type`s (`grant.issued`, `grant.delegated`, `grant.revoked`, `agent.registered`, `agent.revoked`, `trust.established`, `trust.revoked`, `key.revoked`, `approval.approved`, `approval.rejected`) on the same chain (SQLite provider) | one security timeline |
| `policy.provider: opa` with `url`, `timeout_ms`; `policy.file` optional | external PDP |
| `VerifiedChain::to_request` (moved from the gateway) | one place builds requests for gateway, eval and playground |

Planned:

| Change | For |
|---|---|
| `AgentDescriptor.{source, managed, verified, last_seen}` (optional) | discovery |
| Signed policy/trust bundle format (JWS over a tarball manifest, `version`, `not_after`, co-signatures) | GitOps and Console distribution |
| `trust_domains.*.jwks_uri` with pinning | federation without manual key exchange |
| Proof claim `tid` binding the trace id | authenticated cross-gateway correlation (section 5) |

## 4. Crates, modules and repositories

Stay a **monorepo** until a component has its own release cadence and users.

```text
crates/
  nexum-core       model, reason codes, stages            (unchanged boundary)
  nexum-grant      grants, proofs, trust store
  nexum-policy     built-in PDP
  nexum-audit      hash-chained audit
  nexum-gateway    runtime; eval runner, simulate, OPA PDP, risk, discovery
  nexum-sim        scenario DSL, minting, in-memory pipeline (wasm-safe)
  nexum-playground wasm build of nexum-sim for the docs site
  nexum-cli        `nexum`, including the local console (`nexum console`)
evals/             official security suite + fixture gateway
website/           docs site (Astro Starlight), deployed to GitHub Pages
action.yml         GitHub Action for evals
```

`nexum-gateway::eval` stays inside the gateway crate while it needs the
gateway's private build path and adapters; it moves to `nexum-eval` when a
second consumer (the Console) needs it. It has no route on the gateway's HTTP
server; only `nexum eval run` invokes it.

A separate private `nexum-console` repository is created only for the hosted
control plane (Phase 8).

**Outside the Rust runtime:** dashboards, trace search and storage, trust
graph queries, risk scoring, discovery crawlers, SaaS auth/SSO/billing, Hub,
website, SDKs other than Rust. The runtime emits audit events, spans and
metrics; everything else reads them.

## 5. Authority tracing

An **authority trace** answers: *who authorized this action, and how did that
authority travel?* It is not an LLM trace and never contains prompts, model
output, request bodies, tokens, proofs or keys.

**Model.** One trace = ordered **hops** (network calls a gateway decided on),
each carrying its **logical delegation chain** (root holder → … → presenting
agent). These differ by design: one call can carry a three-agent chain, three
calls can carry one grant.

```text
SecurityTrace { id, hops: [Hop] }
Hop {
  audit_log, seq, event_hash,              # provenance (verified chain)
  timestamp, request_id, decision_id, protocol,
  actor, organization, agent, delegation_chain[], grant_ids[],
  action, resource, value, purpose,
  checks: [{ stage, status }],             # derived from reason code + order
  decision, reason_code, security_event, policy, approval_id,
}
```

`status` ∈ `PASS`, `FAIL`, `APPROVAL REQUIRED`, `PENDING`, `NOT REQUIRED`,
`NOT EVALUATED`, `RECORDED`. Because the pipeline is ordered and each exit
has its own code, per-check results are *derived*, not stored: no extra audit
volume and no way for stored results to disagree with the code. (One
exception: `NX-5004` can come from the revocation or approval store and is
shown at the chain stage.)

**Sources.** The audit log is authoritative (hash-verified before use). Spans
are a best-effort copy for existing observability backends. Latency lives in
spans and metrics only, not in audit.

**Correlation.** Gateways read W3C `traceparent` and record the trace id in
audit and as the span parent. Today the trace id is **caller-asserted**:
useful for investigation, never used in decisions. Planned: a `tid` claim in
the proof binds the trace id to the holder's signature, so a hop's membership
in a trace becomes verifiable.

**Conventions.** `nexum.authorize` span; attributes `nexum.request.id`,
`nexum.agent.id`, `nexum.organization.id`, `nexum.trust.domain`,
`nexum.actor.id`, `nexum.action`, `nexum.resource`, `nexum.protocol`,
`nexum.delegation.depth`, `nexum.policy.id`, `nexum.decision`,
`nexum.reason_code`, `nexum.security_event`. Metric labels stay low-cardinality:
outcome and security event only.

**Next:** stage timings (`signature_validation_seconds`,
`policy_evaluation_seconds`) as histograms; OTel log export of audit events;
`nexum trace inspect --policy <file>` (incident replay against another policy).

## 6. Nexum Eval DSL

```yaml
apiVersion: nexum.dev/v1alpha1
kind: EvalSuite
category: delegation
org: partner.example
scenarios:
  - name: worker-cannot-execute-payment
    description: …
    invariant: A sub-agent cannot exercise authority its parent did not delegate.
    grants: [ {sub, cap, res, dcap, max_depth, actor, purpose, max_value, ttl_seconds}, … ]
    attack: replay            # optional
    request: { action, resource, value } | { mcp: {target, message|raw} } | { a2a: {…} }
    expect: DENY
    code: NX-4032
```

Design choices:

- **A grant list instead of `parent`/`child`**: any depth; mutation attacks
  are just a child overriding an inherited field.
- **Signed as written**: the runner mints delegations without the CLI's
  issue-time checks, so the *verifier* is what's tested.
- **Real pipeline, fake world**: fresh sandbox per scenario, ephemeral issuer
  key, in-memory state, upstreams never called.
- **Generated attacks**: every ALLOW baseline is re-run under 12 attacks.
- **Deterministic scoring**: critical = more permissive than expected. Even
  when models later generate adversarial variants (prompt injection, encoded
  arguments), the score is whether an unauthorized operation was *allowed*.

**Next:** `nexum policies simulate <new-policy>` re-evaluating audit history
(needs the `value`/`purpose` fields now recorded) with a DENY→ALLOW impact
report; `--baseline results.json` for cross-version diffs; PR comments from
the Action; protocol scenarios through the live proxy path.

## 7. Website and docs

Astro Starlight in `website/`, static, deployed by `.github/workflows/website.yml`.
Generated from source to avoid drift: reason codes and one page per code
(`/errors/nx-xxxx/`, which the CLI links to), CLI reference (`--help`),
architecture, threat model, roadmap, this plan, protocol guides.

Current sections → target information architecture:

| Now | Target (adds) |
|---|---|
| Start here | installation, concepts overview |
| Concepts | capabilities, resources, revocation as separate pages |
| Guides (MCP, A2A, Python, evals, tracing, deploy) | frameworks (LangGraph, CrewAI, …), identity (SPIFFE, OIDC), policies (OPA, Cedar), cloud deploy |
| Reference (CLI, HTTP, config, reason codes) | policy schema, audit event schema, OpenAPI, rustdoc links |
| Security (overview, threat model, architecture) | cryptography, proof of possession, release signing, SBOM |
| — | Playground |

**Playground** (built): `nexum-playground` compiles `nexum-sim` (verifier,
attenuation and trust checks, built-in PDP) to `wasm32-unknown-unknown`; the
page mints real grants with throwaway keys and runs the pipeline locally.
Randomness comes from `crypto.getRandomValues` through a plain wasm import
(no wasm-bindgen). `nexum-sim/tests/agreement.rs` holds the in-memory
pipeline to the gateway's results on the official suite. **Versioned docs**
start at v0.2.

## 8. Local Console (Phase 6, built)

A developer UI over local files, not a control plane.

```text
nexum console --listen 127.0.0.1:7070 --as <operator>
  ├─ read-only: audit (SQLite opened read-only, chain verified), state.db,
  │             trust.yaml, policy.yaml, eval results (--json files)
  ├─ views: decisions & authority traces, agents, trust, policies, approvals,
  │         eval runs
  └─ actions: approve/reject, revoke — through the same `State` functions as
              the CLI, so every action is audited identically
```

- A CLI subcommand with its own HTTP server; the gateway's router has no
  console routes.
- Loopback only (non-loopback binds are refused); a random per-session token
  in the URL fragment, sent as a bearer header, which also defeats CSRF; Host
  header checked against the listener (DNS rebinding); strict CSP.
- **No authority in the browser**: it never holds the org signing key and
  cannot issue grants. Approval is a request-bound state change in the
  runtime's store, exactly as `nexum approvals approve`.
- Static frontend embedded in the binary; no external assets.

## 9. Hosted Console (Phase 8, design only)

```text
             NEXUM CONSOLE (SaaS / hybrid / private / on-prem)
   fleet · traces · trust graph · risk · approvals · policy history
                          ▲            │ signed bundles (pull)
       metadata (push,    │            ▼
       customer-initiated)│
 ─────────────── customer boundary ─────────────────────────────
                     NEXUM RUNTIME  ── sensitive systems
```

- **Outbound only.** Runtime pulls signed config bundles and pushes audit
  metadata over mTLS with customer-managed certificates. No inbound access.
- **Signed configuration.** Bundles are versioned, signed by the Console *and*
  co-signed by a customer key held outside the Console, so a compromised
  Console cannot push policy alone. Runtime verifies before activation and
  keeps the previous bundle for rollback.
- **Offline.** Runtime enforces the last good bundle when the Console is
  unreachable. Each bundle has `not_after`; on expiry the runtime keeps
  enforcing and raises `enforcement_failure` alerts, unless the operator chose
  `on_expiry: deny`. Never "allow everything".
- **Data minimization.** Exported by default: audit events (ids, decisions,
  codes, chain subjects). Never by default: payloads, prompts, model output,
  credentials. Per-field redaction for actor ids and resources.
- **Configuration as code.** Everything the UI edits exports to YAML in Git;
  the GitOps path (PR → eval → simulate → approve → merge → runtime pulls
  signed bundle) is the primary workflow, the UI a view of it.
- Tenancy, SSO/RBAC, separation of duties for approvals and trust changes.

## 10. Discovery, trust graph, risk, Hub

**Discovery** (Phase 7): passive adapters (Kubernetes, MCP server lists, A2A
Agent Cards) emit `AgentDescriptor`s with `source`, `managed` (has a Nexum
identity), `last_seen`. Read-only; never modifies workloads.

**Trust graph** (Phase 9): nodes (organizations, humans, agents, tools,
resources, trust domains) and edges (`delegated`, `can_access`, `trusts`,
`acts_for`, `called`) built from trust stores, policies, registry and audit.
Queries like "which external agents can reach `erp://*`?" run on the graph,
never in the decision path.

**Risk**: explainable findings, no opaque model scores. A score never hides
its findings.

```text
Risk HIGH
  + payment.execute capability        + external trust relationship
  + 24-hour standing grant            + no owner
```

Signals: wildcard capabilities, long or standing grants, delegation depth,
external trust without expiry, missing owner, stale agents, unmanaged
workloads, recent `security_event`s.

**Hub** (Phase 10): a private enterprise directory of Agent Cards plus Nexum
trust metadata (owner, approved, capabilities, required access, risk). Then
federated: organizations publish only what they choose. Not a marketplace.

## 11. CI/CD

- `cargo test` runs the official eval suite on every commit.
- `action.yml`: users run their own suites on policy/trust PRs; job summary
  lists failures, critical ones first.
- Next: `policies simulate` impact in the summary; PR comments; GitLab and
  Azure DevOps templates; benchmark history for verification, policy
  evaluation and end-to-end decisions.

## 12. Build sequence

| Phase | Scope | Status |
|---|---|---|
| 1 | Docs site, error references, security pages | **done** (deploy pending) |
| 2 | Authority traces, OTel, correlation, `trace inspect`, security events | **done** |
| 3 | Eval DSL, runner, official suite, JSON, GitHub Action | **done**; simulate and baselines next |
| 4 | SPIFFE/SPIRE SVIDs, OIDC, RFC 8693 token exchange | next |
| 5 | OPA adapter, then evaluate Cedar/Cerbos/SpiceDB | **OPA done** |
| 6 | Local console | **done** |
| 7 | Discovery: Kubernetes, MCP, A2A | **A2A done**; risk scan done |
| 8 | Hosted console, only after external demand | design (section 9) |
| 9 | Trust graph | design |
| 10 | Hub, private directory first | later |

Threat-model changes for these components are in
[THREAT_MODEL.md](../THREAT_MODEL.md) (threats 25–31).
