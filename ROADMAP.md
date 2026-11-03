# Roadmap

Stability labels: **experimental** (may change or disappear) → **alpha**
(shape settling, breaking changes possible) → **beta** (breaking changes only
with a migration path) → **stable**. All APIs are `nexum.dev/v1alpha1` today.

Nexum is organized as product tracks around one runtime. The runtime never
depends on the others. Design and sequencing: [docs/PLATFORM.md](docs/PLATFORM.md).

## Next up

In priority order. Each item is small enough to be one pull request or one
decision; the tracks below hold the longer-term list.

**Decisions needed**

1. **Identity beyond Ed25519.** SPIRE SVIDs, OIDC and RFC 8693 token exchange
   need ES256/RS256 or mTLS, which relaxes the Ed25519-only rule. Decide the
   algorithm policy, then build SPIRE JWT-SVID as the first holder proof.
2. **crates.io names.** `nexum` and `nexum-core` belong to other projects.
   Pick a prefix (e.g. `nexum-cli` + `nexum-authz-*`) or stay on GitHub
   releases and ghcr.io only. Publishing also needs a `CARGO_REGISTRY_TOKEN`
   secret.
3. **`unsafe` badge.** The README says "unsafe: forbidden", true for runtime
   crates only; the playground's wasm shim uses ~40 lines. Reword the badge,
   or move the playground to `wasm-bindgen` and drop the shim.

**Credibility**

4. Independent security review of `nexum-grant` (verifier, proofs) and the
   gateway pipeline; publish the report.
5. Get 10–20 external developers through the cross-company demo and the
   playground; collect where the model breaks.
6. Benchmarks in CI: chain verification, policy evaluation, audit write,
   end-to-end decision latency.

**Runtime**

7. Shared replay cache and state so more than one gateway replica can run.
8. Native TLS/mTLS listener and rate limiting.
9. Administrative audit events for the JSONL provider (writer lock).
10. Envoy `ext_authz` and an HTTP reverse-proxy mode.

**Eval and policy**

11. Policy-impact PR comments from the GitHub Action (`policies simulate` +
    `eval run --baseline`).
12. `policies simulate` for trust-store changes.
13. Cedar adapter behind `PolicyDecisionPoint`.

**Developer**

14. TypeScript client, then framework examples (CrewAI, Mastra, OpenAI
    Agents SDK, Google ADK).
15. Kubernetes and MCP server discovery.
16. Versioned docs from v0.2; GitHub Discussions and a public RFC process.

## Shipped (v0.1)

| Area | Status |
|---|---|
| Canonical model, SPIFFE IDs, capability/resource patterns | alpha |
| Delegation grants (EdDSA JWS), attenuation, chain verification | alpha |
| Proof of possession, replay protection | alpha |
| Local trust store with per-domain allow/deny | alpha |
| Local revocation (agent, grant, key, trust domain) | alpha |
| Built-in policy engine, `policies validate/test` | alpha |
| ALLOW / DENY / REQUIRE_APPROVAL with single-use, request-bound approvals | alpha |
| Hash-chained audit (JSONL, SQLite) | alpha |
| REST decision API | alpha |
| MCP enforcement proxy (2026-07-28, Streamable HTTP) | experimental |
| A2A v1.0 JSON-RPC enforcement proxy, Agent Card export | experimental |
| Authority tracing: `nexum.authorize` spans, semantic conventions, security events, OTLP export, `traceparent` correlation, `nexum trace inspect` | experimental |
| Nexum Eval: `EvalSuite` DSL, `nexum eval run`, 12 built-in attacks, official suite, GitHub Action | experimental |
| Prometheus metrics | experimental |
| Docs site, generated reason-code and CLI reference, browser playground (wasm) | experimental |
| Administrative audit events, `policies simulate`, eval baselines | experimental |
| OPA policy provider | experimental |
| Local console, `risk scan`, passive A2A discovery | experimental |
| Local agent registry, Python client, LangGraph example | experimental |
| Release binaries (Linux, macOS, Windows), container on ghcr.io, SBOM, build provenance | v0.1.0 |

## Runtime

* **Identity:** SPIFFE/SPIRE (JWT-SVID / X.509-SVID as holder proof), OIDC and
  workload identity federation for issuers (Entra ID, Okta, Auth0, AWS IAM,
  GCP Workload Identity, Kubernetes service accounts).
* **Delegation:** RFC 8693 token-exchange endpoint to mint root grants from an
  IdP token; track emerging agent-authorization standards.
* **Federation:** `jwks_uri` with pinning and caching; signed trust bundles;
  SPIFFE federation.
* **Policy adapters:** evaluate Cedar, Cerbos, SpiceDB behind
  `PolicyDecisionPoint` (OPA shipped).
* **Gateway:** native rustls listener and mTLS; HTTP reverse-proxy mode;
  Envoy `ext_authz`; shared replay cache and state for HA; rate limiting.
* **Config:** signed, versioned, rollback-capable policy/trust bundles.
* **Keys:** KMS/HSM signers (AWS KMS, Azure Key Vault, GCP KMS, Vault Transit,
  PKCS#11).
* **Audit:** administrative events for the JSONL provider (writer lock);
  PostgreSQL, Kafka, OpenTelemetry logs, SIEM; external anchoring of chain heads.
* **Tracing:** stage timing histograms; proof-bound trace ids; field
  redaction.
* **Performance:** benchmarks with history in CI (verification, policy,
  audit write, end-to-end).
* **Distribution:** crates.io (see Next up), Homebrew, Helm. GitHub
  releases, ghcr.io, SBOM and provenance shipped in v0.1.0.

## Eval

* Trust-store changes in `policies simulate`; simulation for OPA policies.
* PR comments from the GitHub Action; GitLab and Azure DevOps templates.
* Larger attack library; protocol scenarios through the live proxy path.
* Model-generated adversarial variants (prompt injection, encoded arguments),
  always scored deterministically on whether an unauthorized action was allowed.

## Console

* **Local console:** eval-run history, risk findings and policy diffs in the UI.
* **Later, only with external demand:** hosted/hybrid/private control plane
  with fleet, central audit, trust graph, explainable risk, approvals,
  GitOps-driven policy distribution, SSO/RBAC.
* **Discovery:** passive Kubernetes and MCP server discovery (A2A Agent
  Cards shipped).

## Hub

* Private enterprise agent directory (Agent Cards + Nexum trust metadata).
* Later: federated directories where organizations publish only what they
  choose. Not an open marketplace.

## Developer

* Framework adapters: CrewAI, Mastra, OpenAI Agents SDK, Semantic Kernel,
  Google ADK; TypeScript and Go clients.
* Docs: framework and identity guides, versioned docs from v0.2.
* Community: GitHub Discussions, public RFCs for major changes.

## Not planned

An LLM, an agent framework, an LLM-observability product, MCP/A2A
replacements, a proprietary PKI or cryptography, a full IAM provider, a
secrets vault, agent hosting, prompt management, model routing, or any
requirement to use a Nexum service for authorization.
