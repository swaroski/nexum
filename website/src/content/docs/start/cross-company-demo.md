---
title: Cross-company demo
description: Two organizations, independent roots of trust, one verifiable chain of authority.
---

```bash
git clone https://github.com/swaroski/nexum && cd nexum
./examples/cross-company/demo.sh
```

The script initializes **XYZ Corporation** (the caller) and **Supplier ABC**
(the receiver) from scratch in a temp directory. Only XYZ's *public* key is
shared with ABC. ABC starts its gateway and XYZ's agents exercise it:

| # | Who | Asks for | Result | Why |
|---|---|---|---|---|
| 1 | procurement | `inventory.read` | `ALLOW` | in grant, trusted, policy allows |
| 2 | inventory-checker (delegated) | `inventory.read` | `ALLOW` | valid attenuated delegation |
| 3 | inventory-checker | `payment.execute` | `DENY NX-4032` | not present in the delegation chain |
| — | inventory-checker | *mint itself* `payment.execute` | refused | `NX-1015` parent forbids further delegation |
| 4 | procurement | `quote.create` $250,000 | `REQUIRE_APPROVAL` | policy: approval above $100k |
| 5 | procurement + approval | same quote | `ALLOW NX-4003` | approved, consumed once |
| 6 | procurement | anything | `DENY NX-3003` | ABC revoked trust in XYZ |

![Cross-company sequence](/nexum/diagrams/cross-company.light.png)

## Then attack it

The repository ships an eval suite for the same setup:

```bash
nexum -c abc/nexum.yaml eval run examples/cross-company/eval.yaml
```

It runs the scenarios above plus generated attacks (replay, stolen grant,
expired chain, wrong audience, untrusted issuer, tampering, revoked parent,
body swap). See [Security evals](/nexum/guides/evals/).
