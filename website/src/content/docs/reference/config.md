---
title: Configuration
description: nexum.yaml, the gateway configuration.
---

`nexum init` writes a working `nexum.yaml`. Unknown keys are errors: a typo in
security configuration never silently falls back to a default. Relative paths
resolve against the config file's directory.

```yaml
apiVersion: nexum.dev/v1alpha1
server:
  listen: 127.0.0.1:8080
gateway:
  audience: abc.com              # grants and proofs must be addressed to this
  clock_skew_seconds: 30         # default 30
  proof_max_age_seconds: 60      # default 60
  approval_ttl_seconds: 3600     # default 3600
  max_body_bytes: 1048576        # default 1 MiB
policy:  { provider: builtin, file: policy.yaml }  # or: { provider: opa, url: http://127.0.0.1:8181/v1/data/nexum/authz/decision, timeout_ms: 500 }
audit:   { provider: sqlite, path: audit.db }     # or: jsonl, audit.jsonl
trust:   { file: trust.yaml }
state:   { file: state.db }                        # registry, revocations, approvals

mcp:                                # optional: MCP servers at /mcp/{name}
  payments:
    url: http://127.0.0.1:9000/mcp
    tools:
      refund: { action: refund.create, value_argument: amount }

a2a:                                # optional: A2A agents at /a2a/{name}
  supplier:
    url: http://127.0.0.1:9100/a2a/v1
```

The other files: [`trust.yaml`](/nexum/concepts/trust/) and
[`policy.yaml`](/nexum/concepts/policy/).

## Environment

| Variable | Effect |
|---|---|
| `NEXUM_CONFIG` | config path (same as `-c`) |
| `RUST_LOG` | log level / filter, default `info` |
| `NEXUM_LOG_FORMAT=json` | JSON logs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | export decision spans over OTLP/HTTP |
| `OTEL_SERVICE_NAME` | default `nexum-gateway` |
