---
title: Security evals
description: Attack your own trust and policy configuration in CI with nexum eval.
---

Nexum Eval answers one question: **could this agent obtain or exercise
authority it should not have?** It isn't an LLM-quality eval. Scenarios run
through the **real** enforcement pipeline: real signatures, delegation chains,
trust store, policy and MCP/A2A adapters.

- Each scenario gets a fresh sandbox built from your gateway's config, so
  revocations and replay caches never leak between scenarios.
- Production state and audit are never touched, and upstream MCP servers and
  A2A agents are never called.
- The calling organization's keys are swapped for an ephemeral key, so suites
  never need access to a real signing key.
- Delegations are signed exactly as written, so escalation attempts reach the
  verifier instead of being refused at issue time.

```bash
nexum -c gateway/nexum.yaml eval run evals/              # files or directories
nexum -c gateway/nexum.yaml eval run evals/ --json       # for CI and dashboards
```

```text
NEXUM SECURITY EVAL

94 scenarios

  PASS      partner-agent-reads-inventory
  …
  CRITICAL  injected-50k-refund: expected DENY NX-4035, got ALLOW NX-4001  (evals/prompt-injection.yaml)

PASS 93   FAIL 1   CRITICAL 1   score 98.9%

CRITICAL  injected-50k-refund
  Expected DENY, actual ALLOW: the gateway granted authority it should not have.
  Invariant: No prompt or model output can raise what an agent may do.
```

A failure is **critical** when the gateway was *more permissive* than expected
(DENY expected, ALLOW or REQUIRE_APPROVAL observed). The command exits
non-zero on any failure.

## The official suite

The repository ships [`evals/`](https://github.com/swaroski/nexum/tree/main/evals):
94 scenarios against a fixture gateway, run on every commit.

| Suite | What it attacks |
|---|---|
| `identity` | foreign subjects, over-long grants, plus every built-in attack |
| `delegation` | escalation, amplification, depth, resource/lifetime/value widening, actor and purpose mutation, policy depth limits |
| `federation` | partner self-granted capabilities, unknown capabilities, cross-tenant resources, approvals |
| `prompt-injection` | the support refund agent: a "refund $50,000" injection, bank-detail changes, missing amounts, compromised sub-agents |
| `confused-deputy` | a worker borrowing its deputy's broader capabilities or resources |
| `protocol` | MCP tool escalation, unmapped tools, duplicate-key parser differentials, A2A method escalation |

```bash
nexum -c evals/gateway/nexum.yaml eval run evals
```

Copy a suite next to your own gateway config and edit it to encode your
organization's invariants.

## Writing a suite

```yaml
apiVersion: nexum.dev/v1alpha1
kind: EvalSuite
category: delegation
org: partner.example                    # the caller; must be in the trust store
scenarios:
  - name: worker-cannot-execute-payment
    description: A compromised worker tries a capability nobody delegated to it.
    invariant: A sub-agent cannot exercise authority its parent did not delegate.
    grants:                             # root first, then each delegation
      - sub: spiffe://partner.example/agents/procurement
        cap: [inventory.read, pricing.read]
        res: ["erp://acme/*"]
        dcap: [inventory.read]
        max_depth: 1
      - sub: spiffe://partner.example/agents/worker
        cap: [inventory.read]
    request: { action: payment.execute, resource: "erp://acme/invoice/9", value: 10 }
    expect: DENY
    code: NX-4032                       # optional; checked when present
```

A chain of grants, rather than fixed parent/child fields, lets one scenario
express any delegation depth.

**Grant fields:** `sub`, `cap`, `res` (required on the root; inherited
otherwise), `dcap`, `max_depth`, `actor`, `purpose`, `max_value` (all
inherited by delegations unless set, which is how mutation attacks are written),
and `ttl_seconds` (default 300).

**Requests** are one of:

```yaml
request: { action: refund.create, resource: "order://1", value: 200 }       # decision API
request:
  mcp: { target: erp, message: { jsonrpc: "2.0", id: 1, method: tools/call, params: { name: lookup_stock } } }
request:
  mcp: { target: erp, raw: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}' }
request:
  a2a: { target: sales, message: { jsonrpc: "2.0", id: 1, method: SendMessage, params: {} } }
```

`target` names an MCP server or A2A agent in the gateway's `nexum.yaml`.
`expect` is `ALLOW`, `DENY` or `REQUIRE_APPROVAL`.

## Built-in attacks

Every scenario that expects `ALLOW` is re-run under each attack, and each run
must be denied with the listed code. You can also set `attack:` on a scenario.

| Attack | What it does | Must fail with |
|---|---|---|
| `replay` | sends the same request and proof twice | `NX-2004` |
| `stolen-grant` | another key signs the proof for the leaf's grants | `NX-2002` |
| `expired` | the whole chain expired an hour ago | `NX-1008` |
| `stale-proof` | the proof was signed ten minutes ago | `NX-2003` |
| `wrong-audience` | the chain was issued for a different gateway | `NX-1011` |
| `untrusted-issuer` | the root is signed by a key the gateway doesn't trust | `NX-1007` |
| `unknown-organization` | the root claims an organization the gateway doesn't know | `NX-1006` |
| `tampered` | the root's lifetime is extended after signing | `NX-1005` |
| `revoked-parent` | the root grant is revoked | `NX-3002` |
| `revoked-agent` | the requesting agent is revoked | `NX-3001` |
| `revoked-trust` | the receiving organization revokes trust in the caller | `NX-3003` |
| `body-swap` | the proof signs a different body than the one sent | `NX-2005` |

## In CI

The repository is also a GitHub Action. It builds `nexum` at the ref you pin,
runs your suites, fails the job on any failure, and writes a summary table
with critical failures to the job page:

```yaml
- uses: actions/checkout@v4
- uses: swaroski/nexum@main          # pin a commit or tag
  with:
    config: gateway/nexum.yaml
    paths: gateway/evals
```

Run it on pull requests that touch `policy.yaml` or `trust.yaml`. Because the
suite pins expected outcomes, a policy change that widens authority fails the
build until someone updates the expectation, which makes the review explicit.

## Regression testing

Keep a previous run's `--json` output and compare against it:

```bash
nexum eval run evals --json > baseline.json          # on main, or the previous release
nexum eval run evals --baseline baseline.json        # on the change
```

```text
REGRESSIONS against baseline 0.1.0 (100.0%):
  prompt-injection/injected-50k-refund
```

A regression is a scenario that passed in the baseline and fails now. `--json`
output includes `nexum_version`, `score` and `regressions`.

## Policy simulation

Evals check the invariants you wrote down. `nexum policies simulate` checks a
proposed policy against **what actually happened**: it replays recorded
decisions from the audit log under the new policy.

```bash
nexum policies simulate policy-new.yaml --fail-on-widen
```

```text
POLICY IMPACT  policy-new.yaml vs abc/policy.yaml

  Decisions replayed:        6
  Decided before policy:     2  (identity, proof, authority or trust; unaffected)
  Re-evaluated:              4
    unchanged                2
    REQUIRE_APPROVAL → ALLOW 2

  Affected agents: 1   organizations: 1

HIGH-RISK CHANGE: 2 recorded decision(s) would become more permissive
  ▲ spiffe://xyz.com/agents/procurement  quote.create supplier://abc/quote/new value 250000  REQUIRE_APPROVAL → ALLOW  (quote-needs-approval → quote-auto)
```

Only decisions that reached the policy stage are re-evaluated: policy runs
after chain authority and trust, so a policy change cannot affect earlier
denials. `--fail-on-widen` exits non-zero if any decision would become more
permissive, for use in CI next to the eval suite. `--audit` replays other logs;
`--json` gives every change.
