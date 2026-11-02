# Roadmap

Stability labels: **experimental** (may change or disappear) → **alpha**
(shape settling, breaking changes possible) → **beta** (breaking changes only
with a migration path) → **stable**. All APIs are `nexum.dev/v1alpha1` today.

## v0.1 — foundation (this release)

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
| Local agent registry | experimental |
| Python client, LangGraph example | experimental |
| Prometheus metrics | experimental |

## Next

* **Identity:** SPIFFE/SPIRE (JWT-SVID / X.509-SVID as holder proof), OIDC and
  workload identity federation for issuers (Entra ID, Okta, Auth0, AWS IAM,
  GCP Workload Identity, Kubernetes service accounts).
* **Delegation:** RFC 8693 token-exchange endpoint to mint root grants from
  an IdP token; track emerging agent-authorization standards and add them as
  alternative grant formats.
* **Federation:** `jwks_uri` with pinning and caching; signed trust bundles;
  SPIFFE federation.
* **Policy adapters:** OPA, Cedar, Cerbos, SpiceDB behind `PolicyDecisionPoint`.
* **Gateway:** native rustls listener and mTLS; HTTP reverse-proxy mode with
  route → action mapping; Envoy `ext_authz`; shared replay cache and state for
  HA; rate limiting.
* **Audit:** PostgreSQL, Kafka, OpenTelemetry logs, SIEM; external anchoring
  of chain heads.
* **Approvals:** Slack, Teams, email, enterprise workflow integrations;
  separation of duties.
* **Keys:** KMS/HSM signers (AWS KMS, Azure Key Vault, GCP KMS, Vault Transit,
  PKCS#11).
* **Framework adapters:** CrewAI, Mastra, OpenAI Agents SDK, Semantic Kernel,
  Google ADK, TypeScript client.
* **Discovery:** Kubernetes, MCP server and A2A registry discovery into the
  local registry.
* **Tooling:** policy simulation against recorded audit history; benchmarks
  (policy evaluation, signature validation, chain validation, gateway
  throughput); Helm chart.

## Later (separate, optional)

* Control plane: fleet inventory, policy and trust distribution, approvals UI,
  audit search, risk and compliance reporting. SaaS, hybrid, private or
  on-prem. Never on the request path.
* Federated and public agent directory, with trust derived from the
  identity/trust fabric above.

## Not planned

An LLM, an agent framework, MCP/A2A replacements, a proprietary PKI or
cryptography, a full IAM provider, a secrets vault, agent hosting, prompt
management, model routing.
