# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
break compatibility.

## [Unreleased]

### Fixed
- `examples/cross-company/demo.sh` left its gateway running on exit.
- The gateway now shuts down gracefully on SIGTERM. As a container's PID 1 it
  previously ignored `docker stop` / Kubernetes termination until SIGKILL.

### Added
- Canonical authorization model (`nexum-core`): SPIFFE agent IDs, capability
  and resource patterns, requests, decisions, stable `NX-xxxx` reason codes.
- Delegation grants (EdDSA JWS) with attenuation, holder-of-key binding,
  chain verification and request-level proof of possession (`nexum-grant`).
- Local trust store with per-trust-domain allow/deny lists.
- Built-in declarative policy engine (`nexum-policy`).
- Hash-chained audit log, JSONL and SQLite (`nexum-audit`).
- Gateway with REST decision API, MCP and A2A enforcement proxies, local
  registry, revocations, approvals, Prometheus metrics (`nexum-gateway`).
- Nexum Eval: `nexum eval run [paths] [--json]` runs `EvalSuite` scenarios
  (decision API, MCP and A2A requests) through the real pipeline in a fresh
  sandbox per scenario, re-running every ALLOW case under 12 built-in attacks
  and flagging more-permissive-than-expected results as critical. Official
  suite in `evals/` (94 scenarios); GitHub Action in `action.yml`.
- Authority tracing: `nexum.authorize` spans with `nexum.*` semantic
  conventions, OTLP/HTTP export, W3C `traceparent` correlation, JSON logs,
  `nexum trace inspect` (per-check results and delegation path from the
  verified audit log, across several gateways' logs).
- Stable security events (`ReasonCode::security_event`) as a span attribute
  and `nexum_security_events_total`; pipeline stages (`ReasonCode::stage`).
- Audit events record `trace_id`, delegation `chain`, `value` and `purpose`
  (omitted when empty; existing logs still verify).
- `nexum call` and `trace inspect` link to a docs page per reason code.
- Documentation site (`website/`, Astro Starlight) with repository docs,
  reason codes, per-code error pages and CLI reference generated from source.
- `docs/PLATFORM.md`: Runtime/Eval/Console/Hub plan; roadmap by product track;
  threat model entries 25–31.
- Administrative audit events (`grant.issued`, `grant.delegated`,
  `agent.registered`/`revoked`, `trust.established`/`revoked`, `key.revoked`,
  `approval.approved`/`rejected`) with `operator` and `detail`, on the same
  hash chain as decisions (SQLite provider).
- `nexum policies simulate`: replay audited decisions under a proposed policy;
  `--fail-on-widen` for CI.
- `nexum eval run --baseline`: report regressions against an earlier run.
- OPA policy provider (`policy.provider: opa`), fail-closed; Rego example.
- `nexum console`: local web UI (loopback, per-session token, Host check).
- `nexum risk scan` (explainable findings) and `nexum discover a2a` (passive
  Agent Card discovery).
- `nexum-sim` (scenario DSL, minting, in-memory pipeline held to the gateway's
  results) and `nexum-playground` (wasm) powering the docs-site playground.
- `nexum` CLI, cross-company demo, Python client, LangGraph example, Docker.
