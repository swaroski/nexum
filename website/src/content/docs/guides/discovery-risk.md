---
title: Discovery and risk
description: Find agents Nexum doesn't manage, and explainable findings about your trust and policy.
---

## Discover A2A agents

```bash
nexum discover a2a https://sales.abc.example https://10.0.0.7:9000/.well-known/agent-card.json
```

```text
1 agents discovered: 0 managed, 1 unmanaged

Shadow pricing bot  (unknown provider)
  card:      http://10.0.0.7:9000/.well-known/agent-card.json
  endpoints: http://10.0.0.7:9000/a2a
  skills:    pricing.read
  auth:      -
  managed:   no
  ! unmanaged: no registered Nexum identity serves this endpoint
  ! declares no authentication scheme
  ! endpoint without TLS
```

Discovery is **passive**: it fetches Agent Cards (A2A v1.0
`supportedInterfaces`, or v0.3 `url`) and compares their endpoints with the
local registry. It never registers, modifies or calls the agents. `--json` for
inventories. Kubernetes and MCP discovery are on the
[roadmap](/nexum/project/roadmap/).

## Risk scan

```bash
nexum risk scan            # --days 7 --json
```

```text
NEXUM RISK SCAN  abc.com  (audit: last 7 days)

HIGH 1   MEDIUM 1   LOW 0

HIGH    activity.security_events       spiffe://xyz.com/agents/inventory-checker
        privilege_escalation_attempt ×1
        fix: Inspect with `nexum audit search --agent …` and `nexum trace inspect`; revoke if compromised.

MEDIUM  trust.wildcard                 abc.com
        own organization may exercise *
        fix: List the capabilities you accept from this organization explicitly; policy should not be the only limit.
```

Every finding has a stable id, its evidence and a fix. There is no aggregate
score, because a number would hide the findings. The command exits non-zero
on any HIGH finding, so it can run in CI.

| Finding | Severity | When |
|---|---|---|
| `trust.wildcard` | HIGH (partner) / MEDIUM (own) | trust allows `*` or `x.*` |
| `trust.high_impact` | MEDIUM | a partner is trusted for payment/refund/export/delete/… |
| `trust.long_lived_grants` | MEDIUM | `max_grant_ttl_seconds` above one hour |
| `policy.wildcard_allow` | HIGH | an allow rule for a wildcard action on any resource |
| `policy.unbounded_high_impact` | MEDIUM | a high-impact allow with no value limit or approval |
| `policy.unbounded_delegation` | LOW | no `delegation.allowed` or `max_depth` |
| `policy.any_organization` | LOW | a policy applies to `organization: "*"` |
| `agent.no_owner` | LOW | an active agent has no owner |
| `activity.security_events` | HIGH / MEDIUM | recent [security events](/nexum/guides/observability/#security-events) per agent |
