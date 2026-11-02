# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may
break compatibility.

## [Unreleased]

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
- `nexum` CLI, cross-company demo, Python client, LangGraph example, Docker.
