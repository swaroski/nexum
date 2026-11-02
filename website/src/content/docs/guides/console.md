---
title: Local console
description: A web UI over one gateway's audit, registry, trust, policy and approvals. Runs on your machine; no SaaS.
---

```bash
nexum -c abc/nexum.yaml console            # --listen 127.0.0.1:7070 --as cfo@abc.com
```

```text
Nexum console for abc/nexum.yaml
  http://127.0.0.1:7070/#token=a2729418…
  acting as cfo@abc.com (approvals and revocations are audited under this name)
```

Open the printed URL. The console shows:

- **Overview:** decisions, approvals and security events in the last 24 hours;
  agents, trusted organizations and revocations.
- **Decisions:** every audit event, including administrative ones, with a link
  to each decision's [authority trace](/nexum/guides/observability/#inspect-a-decision).
- **Agents, Trust, Policy:** the registry, trust store (with revocations) and
  policy as the gateway sees them.
- **Approvals:** approve or reject pending requests.

Approving, rejecting and revoking use the same state functions as the CLI and
write the same audit events (`approval.approved`, `agent.revoked`, …) under the
`--as` name. Every page re-verifies the audit hash chain before showing it.

## Security

The console is a local, single-operator tool, not a control plane:

- It only binds loopback addresses; anything else is refused.
- Every API call needs the per-session token from the printed URL, sent as a
  header, so other sites can't make requests on your behalf. CORS is off.
- Requests with any other `Host` header are rejected, which blocks DNS rebinding.
- It never holds the organization signing key and cannot issue grants.
- Approvals stay single-use and request-bound; the browser only changes their state.

For remote access, use SSH port forwarding rather than binding elsewhere.
