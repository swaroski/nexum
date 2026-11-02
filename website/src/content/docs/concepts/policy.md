---
title: Policy language
description: The built-in, deliberately small policy engine.
---

```yaml
apiVersion: nexum.dev/v1alpha1
kind: Policy
id: abc-supplier-v1
subjects:
  - organization: xyz.com            # or "*" for any trusted domain
    agent: spiffe://xyz.com/agents/* # optional; exact ID or prefix ending in *
rules:
  - { id: inventory-read, action: inventory.read, resource: "supplier://abc/*", effect: allow }
  - { id: quote-auto,     action: quote.create, effect: allow,    conditions: { max_value: 100000 } }
  - { id: quote-approval, action: quote.create, effect: approval, conditions: { value_above: 100000 } }
  - { id: no-payments,    action: payment.execute, effect: deny }
delegation:
  allowed: [inventory.read, pricing.read]   # only these may be exercised via delegation
  forbidden: [customer.export]              # never via delegation
  max_depth: 2                              # hops below the root grant
```

One file may hold several policies separated by `---`; ids must be unique.

## Rules

| Field | Meaning |
|---|---|
| `action` | capability pattern, e.g. `inventory.read` or `mcp.payments.*` |
| `resource` | optional resource pattern; absent = any resource |
| `effect` | `allow`, `deny` or `approval` |
| `conditions.max_value` | matches when the request has a value `<= max_value` |
| `conditions.value_above` | matches when the request has a value `> value_above` |
| `conditions.purpose` | matches when the chain's purpose equals this |

A value condition never matches a request without a value.

## Combining

**Deny-overrides**: `DENY` > `REQUIRE_APPROVAL` > `ALLOW`, across every
matching rule of every applicable policy. No matching rule is `DENY NX-4036`.
Unknown fields fail validation, so a typo can't silently widen access.

## Testing before you deploy

```bash
nexum policies validate
nexum policies test --agent spiffe://xyz.com/agents/procurement \
  --action quote.create --resource supplier://abc/quote/new --value 250000
```

For attack-style regression tests in CI, use [`nexum eval run`](/nexum/guides/evals/).
To see what a change would have done to real traffic, replay the audit log with
[`nexum policies simulate`](/nexum/guides/evals/#policy-simulation).

## External engines

[OPA](/nexum/guides/opa/) can replace the built-in engine (`policy.provider:
opa`). Like the built-in engine it runs after chain authority and trust, so it
can only narrow them, and any OPA failure is `DENY NX-5002`. Cedar, Cerbos and
SpiceDB are on the [roadmap](/nexum/project/roadmap/), behind the same
`PolicyDecisionPoint` trait.
