# OPA: Rego as the policy engine

Nexum can ask [Open Policy Agent](https://www.openpolicyagent.org) instead of
its built-in engine. OPA is consulted only after the delegation chain, proof,
chain authority and trust checks pass, so Rego can only narrow what those
allow. [`policy.rego`](policy.rego) is the cross-company demo's policy.

```bash
opa run --server --addr 127.0.0.1:8181 examples/opa/policy.rego
```

```yaml
# nexum.yaml
policy:
  provider: opa
  url: http://127.0.0.1:8181/v1/data/nexum/authz/decision
  timeout_ms: 500        # default
```

**Input:** `{"input": <AuthorizationRequest>}` with `subject`, `actor`,
`organization`, `action`, `resource`, `purpose`, `delegation_chain`,
`authority`, `context.value`, `context.protocol`, `context.attributes`.

**Result:** the rule must evaluate to either `true`/`false`, or
`{"outcome": "ALLOW" | "DENY" | "REQUIRE_APPROVAL", "policy_id": "...", "rule_id": "..."}`.
`REQUIRE_APPROVAL` uses Nexum's single-use, request-bound approvals.

**Fail closed:** an undefined rule (a wrong URL or package), an HTTP error, a
timeout or any other result shape is `DENY NX-5002`. Run OPA as a sidecar
next to the gateway.

`nexum policies test` and `policies simulate` evaluate the built-in engine
only. To test Rego, point a gateway config at OPA and run
`nexum eval run`: the eval sandbox uses whatever policy provider the config names.
