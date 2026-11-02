---
title: Tracing and observability
description: Authority traces, OpenTelemetry semantic conventions, security events, logs and metrics.
---

Nexum doesn't replace your observability stack; it feeds it. It records three
different things, and they answer different questions:

| | Answers | Where | Durability |
|---|---|---|---|
| **Audit** | Who did what, on whose authority, was it allowed, under which policy? | hash-chained SQLite/JSONL, `nexum audit` | the security record; a decision isn't returned until it's written |
| **Authority traces** | How did authority travel, and which check decided? | `nexum trace inspect`, OpenTelemetry spans | built from audit; spans are best-effort |
| **Logs** | Is the gateway healthy? | stderr, `RUST_LOG`, JSON | operational only |

Nexum traces are **authority traces**, not LLM traces. They don't contain
prompts, model output, request bodies, tokens, proofs or keys.

## Inspect a decision

Every decision response carries a `request_id` (and `nexum call` prints the
decision id). Ask the gateway's audit log what happened:

```bash
nexum trace inspect 01a19e10-dee7-74b0-be1a-da4994dc42e2
```

```text
DENY NX-4032

  Request:    01a19e10-dee7-74b0-be1a-da4994dc42e2
  When:       2026-11-02T21:01:08Z  via http
  On behalf:  jane@xyz.com
  Authority:  spiffe://xyz.com/agents/procurement  (root grant from xyz.com)
                ↓ delegated
              spiffe://xyz.com/agents/inventory-checker
  Requested:  payment.execute  supplier://abc/invoice/77  value 9000
  Purpose:    q3-restock

  Identity & delegation chain   PASS
  Proof of possession           PASS
  Request normalization         PASS
  Delegated authority           FAIL
  Organization trust            NOT EVALUATED
  Policy                        NOT EVALUATED
  Human approval                NOT EVALUATED
  Audit                         RECORDED

  Reason:     The requested capability was not present in the delegation chain.
  Security:   privilege_escalation_attempt
  Audit:      event #3 in abc/.nexum/audit.db (chain verified)
  Learn more: https://swaroski.github.io/nexum/errors/nx-4032/
```

The gateway checks in a fixed order, so the reason code identifies which check
decided: earlier ones passed, later ones never ran. `trace inspect` refuses to
explain anything from an audit log that fails hash-chain verification.

`--json` prints the same trace as structured data (see the schema below).

### Across gateways

A request can cross several gateways: XYZ's agent calls ABC's gateway, whose
agent calls an MCP server behind another gateway. If callers propagate a W3C
`traceparent` header, each gateway records the same trace id. Point
`trace inspect` at every audit log you have:

```bash
nexum trace inspect 4bf92f3577b34da6a3ce929d0e0e4736 \
  --audit xyz/audit.db --audit abc/audit.db --audit erp/audit.jsonl
```

Each **hop** is a network call that a gateway decided on. Inside each hop,
**Authority** is the *logical* delegation chain: who delegated to whom. These
differ: one network call can carry a three-agent chain, and three network calls
can all carry the same grant.

:::caution
A trace id is asserted by the caller and is not authenticated. It's for
correlation during investigation; it never affects a decision. Don't treat a
shared trace id as proof that two events are causally linked.
:::

### Trace schema

`nexum trace inspect --json`:

```json
{
  "id": "4bf92f35…",
  "hops": [
    {
      "audit_log": "abc/audit.db",
      "seq": 3,
      "event_hash": "…",
      "timestamp": "2026-11-02T21:01:08Z",
      "request_id": "…",
      "decision_id": "…",
      "protocol": "http",
      "actor": "jane@xyz.com",
      "organization": "xyz.com",
      "agent": "spiffe://xyz.com/agents/inventory-checker",
      "delegation_chain": ["spiffe://xyz.com/agents/procurement", "spiffe://xyz.com/agents/inventory-checker"],
      "grant_ids": ["…", "…"],
      "action": "payment.execute",
      "resource": "supplier://abc/invoice/77",
      "value": 9000,
      "purpose": "q3-restock",
      "checks": [{ "stage": "chain", "status": "PASS" }, "…"],
      "decision": "DENY",
      "reason_code": "NX-4032",
      "security_event": "privilege_escalation_attempt",
      "policy": null,
      "approval_id": null
    }
  ]
}
```

## OpenTelemetry

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 nexum gateway start
```

Spans go over OTLP/HTTP to an OpenTelemetry Collector, which forwards them to
Grafana Tempo, Datadog, Honeycomb, Jaeger, Splunk, Elastic, CloudWatch, Azure
Monitor or Google Cloud Trace. The standard `OTEL_*` variables apply
(`OTEL_SERVICE_NAME` defaults to `nexum-gateway`). If the caller sent a
`traceparent`, the decision span joins the caller's trace.

:::note
The gateway exports plain HTTP to a local or sidecar collector; `https://`
endpoints are refused. Let the collector handle TLS to your backend.
:::

### Semantic conventions

Every decision is one `nexum.authorize` span. Attribute names are stable
within `v1alpha1`:

| Attribute | Example | Notes |
|---|---|---|
| `nexum.request.id` | `01a19cc6-5d2b-…` | joins to the audit log |
| `nexum.agent.id` | `spiffe://xyz.com/agents/inventory-checker` | the presenting agent |
| `nexum.organization.id` | `xyz.com` | the trust domain that issued the root grant |
| `nexum.trust.domain` | `abc.com` | this gateway's trust domain (audience) |
| `nexum.actor.id` | `jane@xyz.com` | the human or service the chain acts for |
| `nexum.action` | `payment.execute` | normalized action |
| `nexum.resource` | `supplier://abc/invoice/77` | normalized resource |
| `nexum.protocol` | `http`, `mcp`, `a2a` | adapter |
| `nexum.delegation.depth` | `1` | hops below the root grant |
| `nexum.policy.id` | `abc-supplier-v1` | matched policy, if any |
| `nexum.decision` | `ALLOW`, `DENY`, `REQUIRE_APPROVAL` | |
| `nexum.reason_code` | `NX-4032` | [reason codes](/nexum/reference/reason-codes/) |
| `nexum.security_event` | `privilege_escalation_attempt` | set only for alert-worthy denials |

Agent, organization and actor come from the *verified* chain, never from
unverified claims; when chain verification fails they are absent.

## Security events

Denials that suggest an attack or an outage carry a stable event name:

| Event | Raised by |
|---|---|
| `invalid_signature` | NX-1003, NX-1004, NX-1005 |
| `unknown_issuer` | NX-1006, NX-1007, NX-1017 |
| `delegation_amplification_attempt` | NX-1012 to NX-1016, NX-1018, NX-1019 |
| `credential_misuse` | NX-2002, NX-2005 |
| `replay_attempt` | NX-2004 |
| `revoked_credential_use` | NX-3001 to NX-3004 |
| `privilege_escalation_attempt` | NX-4031 to NX-4034, NX-4037, NX-4038 |
| `enforcement_failure` | NX-5002, NX-5003, NX-5004 |

Alert on them from spans, logs (`security_event` field) or metrics.

## Metrics

`GET /metrics` serves Prometheus text:

```text
nexum_requests_total
nexum_decisions_total{outcome="allow|deny|require_approval"}
nexum_security_events_total{event="replay_attempt|…"}
nexum_audit_errors_total
nexum_decision_seconds_sum
```

Labels are limited to small fixed sets. Agent, organization and resource ids
are never metric labels; use traces or audit for those.

## Logs

Logs go to stderr. Use `RUST_LOG` for the level and `NEXUM_LOG_FORMAT=json`
for Splunk, Elastic, CloudWatch, Loki or any other log pipeline. Each decision
logs one line with `outcome`, `reason`, `security_event` and `latency_us`
inside the span's fields.
