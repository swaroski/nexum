---
title: HTTP API
description: The decision API, enforcement proxies, health and metrics.
---

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/authorize` | Ask for a decision |
| `POST` | `/mcp/{server}` | Authorize an MCP JSON-RPC message, then forward it |
| `POST` | `/a2a/{agent}` | Authorize an A2A JSON-RPC message, then forward it |
| `GET` | `/healthz` | `ok` |
| `GET` | `/metrics` | Prometheus text |

## Credentials

Credentials travel in headers so the proof can sign the exact body:

| Header | Value |
|---|---|
| `Nexum-Grant` | compact grants, comma-separated, root first |
| `Nexum-Proof` | proof of possession signed by the leaf holder over this body |
| `Nexum-Approval` | approval id, when retrying an approved request |
| `traceparent` | optional W3C trace context; only links tracing |

Nexum credentials and `Authorization` are never forwarded to upstreams.

## `POST /v1/authorize`

```json
{
  "action": "quote.create",
  "resource": "supplier://abc/quote/new",
  "value": 250000,
  "attributes": {}
}
```

`action` and `resource` must be exact (no wildcards). Unknown fields are
rejected (`NX-5001`).

| Outcome | HTTP status |
|---|---|
| `ALLOW` | 200 |
| `REQUIRE_APPROVAL` | 202 |
| `DENY` | 403 |

```json
{
  "decision": {
    "outcome": "REQUIRE_APPROVAL",
    "decision_id": "…",
    "request_id": "…",
    "matched_policy": "abc-supplier-v1",
    "matched_rule": "quote-needs-approval",
    "reason_codes": ["approval_required"],
    "obligations": [{ "type": "human_approval", "approval_id": "…" }],
    "expires_at": "2026-11-02T15:15:08Z"
  },
  "code": "NX-4002",
  "message": "Policy requires human approval for this action."
}
```

## MCP and A2A proxies

Denied and approval-required messages are answered by the gateway with a
JSON-RPC error carrying the same decision body in `error.data`: code `-32001`
for `DENY` (HTTP 403) and `-32002` for `REQUIRE_APPROVAL` (HTTP 202). The
upstream is never called. See the [MCP](/nexum/guides/mcp/) and
[A2A](/nexum/guides/a2a/) guides for the action mapping.
