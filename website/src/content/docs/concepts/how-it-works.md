---
title: How it works
description: The request pipeline, from protocol message to audited decision.
---

The gateway sits in front of what it protects. A protocol adapter (REST, MCP
or A2A) turns the incoming message into a normalized action and resource, then
every request passes the same checks, in order:

| # | Check | Fails with |
|---|---|---|
| 1 | **Delegation chain**: signatures, issuer, attenuation on every hop, time, audience, revocation | `NX-1xxx`, `NX-3xxx` |
| 2 | **Proof of possession**: signed by the leaf holder over the exact body, fresh, single use | `NX-2xxx` |
| 3 | **Normalize**: one exact action and resource; ambiguous messages are rejected | `NX-5001` |
| 4 | **Chain authority**: the chain actually carries this capability, resource and value | `NX-4032`–`NX-4034` |
| 5 | **Trust**: the receiving organization accepts this capability from the caller's domain | `NX-4031` |
| 6 | **Policy**: deny-overrides, default deny | `NX-4035`–`NX-4038` |
| 7 | **Approval**: single-use human approval bound to the exact request, if policy asks | `NX-4004` |
| 8 | **Audit**: one hash-chained event; if the write fails the decision becomes `DENY` | `NX-5003` |

![Request pipeline](/nexum/diagrams/request-pipeline.light.png)

Policy runs *after* chain authority and trust, so policy can only narrow what
the chain and the trust relationship already permit.

## What is local

Everything the gateway needs is a file the customer owns: `trust.yaml`,
`policy.yaml`, `state.db` (registry, revocations, approvals) and the audit log.
No call to any control plane is on the request path. A gateway can run as a
sidecar, a shared gateway, on a laptop, or air-gapped.

## What is deliberately not here

Nexum is not an agent framework, an LLM, an IdP, a PKI, a policy language or a
transport. It sits between those and reuses their standards: SPIFFE IDs,
JWS/JWT, JWK, RFC 8693 `act`, RFC 7800 `cnf`, DPoP-style proofs, MCP and A2A.
See the full [architecture](/nexum/security/architecture/).
