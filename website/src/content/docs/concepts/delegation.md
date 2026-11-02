---
title: Delegation and proofs
description: Grants that only narrow, and per-request proofs that make them useless to thieves.
---

## Grants

A grant is a compact JWS (`typ: nexum-grant+jwt`, `alg: EdDSA` only). A root
grant is signed by an organization's key and names an agent (`sub`), the human
it acts for (`act.sub`), the gateways that may accept it (`aud`), its
capabilities (`cap`), resources (`res`), and how much of that it may pass on
(`dcap`, `mdd`).

A child grant is signed by the **parent's holder key** and links to its parent
by hash (`prt`). On every hop, every request:

```text
authority(child) ⊆ authority(parent)
```

| A child may not | Reason code |
|---|---|
| claim capabilities outside the parent's `dcap` | `NX-1013` |
| claim resources outside the parent's | `NX-1014` |
| delegate when the parent's depth is used up | `NX-1015` |
| outlive its parent | `NX-1016` |
| change actor, purpose or audience | `NX-1018` |
| raise or drop a value limit | `NX-1019` |

A parent never hands its own grant and key to a child; it mints a new,
narrower grant bound to the child's key.

```bash
nexum grants delegate --parent root.jwt --key procurement.key.json \
  --sub spiffe://xyz.com/agents/inventory-checker \
  --holder inventory-checker.key.json --cap inventory.read --ttl 300 --out child.jwt
```

## Proof of possession

Grants are not bearer tokens. Every request also carries a proof
(`Nexum-Proof`) signed by the leaf holder's key, binding:

- this gateway (`aud`),
- the leaf grant (`gh`),
- the SHA-256 of the exact request body (`bh`),
- a fresh `iat` (60 s by default) and a single-use `jti`.

So a stolen grant is useless without the private key (`NX-2002`), a captured
request cannot be replayed (`NX-2004`) or re-targeted, and an intermediary
cannot change the body, such as the MCP tool name or the amount (`NX-2005`).

Clients: `nexum call`, the [Python client](/nexum/guides/python/), or
`nexum_grant::create_proof` in Rust.
