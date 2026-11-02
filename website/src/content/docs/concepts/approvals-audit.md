---
title: Approvals and audit
description: Human-in-the-loop decisions bound to the exact request, and a log you can prove is intact.
---

## Approvals

When policy says `approval`, the gateway returns `REQUIRE_APPROVAL NX-4002`
(HTTP 202) and an approval id. The approval is bound by fingerprint to the
exact subject, actor, organization, action, resource and value.

```bash
nexum approvals list
nexum approvals approve <id> --by cfo@abc.com     # or: reject
```

The agent retries the identical request with `Nexum-Approval: <id>` and a
fresh proof. The gateway re-runs every check and consumes the approval
atomically: `ALLOW NX-4003`, once. A different amount, an expired, rejected or
already-used approval is `NX-4004`. A policy denial still overrides an approval.

## Audit

One event per decision, in SQLite or JSONL, hash-chained:
`event[n].previous_event_hash = event[n-1].event_hash`.

```bash
nexum audit tail -n 50
nexum audit search --agent spiffe://xyz.com/agents/procurement --decision DENY
nexum audit verify          # detects modification, deletion, reordering
```

Events carry ids, decisions, reason codes, grant ids and policy ids, and never
tokens, proofs, keys or request payloads.

Administrative actions are on the same chain, so an investigation sees one
timeline: `agent.registered`, `agent.revoked`, `grant.issued`,
`grant.delegated`, `grant.revoked`, `trust.established`, `trust.revoked`,
`key.revoked`, `approval.approved`, `approval.rejected`. Each records the
`operator` who ran it (the OS user, or `--by`/`--as`; self-reported, not
authenticated). Administrative events need the `sqlite` audit provider, which
is safe to write from the CLI while the gateway runs; with `jsonl` they are
skipped with a warning. If the audit write fails, the
decision becomes `DENY NX-5003`.

For dashboards and tracing, see [Observability](/nexum/guides/observability/).
