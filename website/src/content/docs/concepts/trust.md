---
title: Trust domains and federation
description: Every organization is its own root of trust. There is no Nexum CA.
---

`trust.yaml` is the receiving organization's statement of whom it trusts:

```yaml
apiVersion: nexum.dev/v1alpha1
trust_domains:
  xyz.com:
    issuer: https://identity.xyz.com
    keys: [{ kty: OKP, crv: Ed25519, x: "…", kid: "xyz-2026-11" }]   # standard JWKS
    allow: [inventory.read, pricing.read, quote.create]
    deny:  [payment.execute, customer.export]
    max_grant_ttl_seconds: 3600
```

ABC verifies XYZ's authority with XYZ's published key, then applies **its own**
allow/deny list and **its own** policy. Nobody, including any future Nexum
service, sits in the trust path.

```bash
nexum trust add xyz.com --issuer https://identity.xyz.com --key xyz.jwk.json \
  --allow inventory.read --deny payment.execute
nexum trust list
```

- An organization can only vouch for agents inside its own trust domain
  (`NX-1017`).
- Keys are selected by `kid` *within the claimed domain only*.
- `deny` wins over `allow`, and a capability the domain doesn't allow is
  `NX-4031` even if the grant carries it.

## Revocation

Takes effect on the next request, and kills every descendant grant:

```bash
nexum agents revoke spiffe://xyz.com/agents/procurement   # NX-3001
nexum grants revoke <jti>                                 # NX-3002
nexum trust revoke xyz.com --reason "contract ended"     # NX-3003
nexum trust revoke-key <kid-or-thumbprint>                # NX-3004
```
