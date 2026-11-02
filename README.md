# Nexum

**Zero-trust authorization and delegated identity for AI agents.**

> Secure agent-to-agent, agent-to-tool and cross-organization interactions
> across any framework, cloud, model or protocol.

```text
   LangGraph / CrewAI / Mastra / custom agent   (any model, any cloud)
                        │
                        │  delegation grant chain + proof of possession
                        ▼
                ┌───────────────┐
                │  nexum gateway │  identity · delegation · trust · policy · audit
                └───────┬───────┘
                        │  ALLOW / DENY / REQUIRE_APPROVAL
                        ▼
              MCP tool · A2A agent · REST API · resource
```

An agent's reasoning ("I should refund this customer") is not authorization.
Nexum decides deterministically, next to the resource, from things it can
verify: **who the agent is, which organization vouches for it, who delegated
what authority to it, and what the receiving organization's own policy
allows.** It needs no cloud service, and no vendor sits in the trust path.

> **Status:** v0.1, `nexum.dev/v1alpha1`, experimental. Not yet independently
> security-reviewed. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Demo: two companies, one delegation chain

XYZ Corporation's procurement agent (acting for `jane@xyz.com`) calls Supplier
ABC. ABC trusts only XYZ's public key, for only some capabilities, under its
own policy.

```bash
git clone https://github.com/swaroski/nexum && cd nexum
./examples/cross-company/demo.sh
```

```text
== Request 1: procurement agent reads inventory
ALLOWED NX-4001
  Agent:      spiffe://xyz.com/agents/procurement
  On behalf:  jane@xyz.com
  Requested:  inventory.read  supplier://abc/sku/123
  Chain:      depth 0, capabilities: inventory.read, pricing.read, quote.create
  Policy:     abc-supplier-v1 / inventory-read

== Request 2: procurement delegates ONLY inventory.read to a sub-agent
delegated spiffe://xyz.com/agents/procurement -> spiffe://xyz.com/agents/inventory-checker (inventory.read)
ALLOWED NX-4001
  Chain:      depth 1, capabilities: inventory.read

== Request 3: the sub-agent tries to execute a payment
DENIED NX-4032
  Agent:      spiffe://xyz.com/agents/inventory-checker
  Requested:  payment.execute  supplier://abc/invoice/77
  Reason:     The requested capability was not present in the delegation chain.
  Chain:      depth 1, capabilities: inventory.read

== Request 4: procurement asks for a $250,000 quote
APPROVAL REQUIRED NX-4002
  Policy:     abc-supplier-v1 / quote-needs-approval
  Approval:   01a1999a-6988-77d1-8883-a360a450ad5e

== An ABC approver approves; procurement retries (single use)
ALLOWED NX-4003
  Reason:     A matching human approval was presented and consumed.

== ABC revokes trust in XYZ; everything from XYZ stops immediately
DENIED NX-3003

== ABC's tamper-evident audit trail
#1  ALLOW             spiffe://xyz.com/agents/procurement        inventory.read   NX-4001
#2  ALLOW             spiffe://xyz.com/agents/inventory-checker  inventory.read   NX-4001
#3  DENY              spiffe://xyz.com/agents/inventory-checker  payment.execute  NX-4032
#4  REQUIRE_APPROVAL  spiffe://xyz.com/agents/procurement        quote.create     NX-4002
#5  ALLOW             spiffe://xyz.com/agents/procurement        quote.create     NX-4003
#6  DENY              -                                          -                NX-3003
audit chain intact: 6 events
```

## Quick start

```bash
cargo install --git https://github.com/swaroski/nexum nexum   # Rust 1.87+

nexum init --domain example.com          # config, trust store, policy, org key
nexum agents register --id spiffe://example.com/agents/bot --name bot
nexum grants issue --sub spiffe://example.com/agents/bot \
  --holder .nexum/keys/bot.key.json \
  --cap example.read --cap refund.create --res 'app://*' --aud example.com --out bot.jwt
nexum gateway start &

nexum call --grant bot.jwt --key .nexum/keys/bot.key.json \
  --action refund.create --resource app://orders/42 --value 1700
# APPROVAL REQUIRED NX-4002   (starter policy: automatic up to 500)
```

Or with Docker: `docker compose -f deploy/docker/docker-compose.yml up`.

## How it works

| Concept | What it is |
|---|---|
| **Agent identity** | A [SPIFFE ID](https://spiffe.io), e.g. `spiffe://xyz.com/agents/procurement`, separate from any human. |
| **Trust domain** | An organization's own root of trust. Nobody else's CA is involved. |
| **Delegation grant** | A short-lived, audience-bound, holder-of-key JWT (EdDSA). Each child grant is signed by its parent's holder and can only **narrow** capabilities, resources, audience, lifetime, depth and value limits. |
| **Proof of possession** | Every request carries a fresh signature by the holder over the exact body, so stolen grants and captured requests are useless. |
| **Trust store** | The receiving org's list of whom it trusts, with which keys, for which capabilities. |
| **Policy** | A small declarative engine (deny-overrides, default deny) behind a `PolicyDecisionPoint` trait for OPA/Cedar/Cerbos/etc. |
| **Approvals** | First-class, single-use, bound to one exact request. |
| **Audit** | One hash-chained event per decision; never contains tokens or payloads. |
| **Adapters** | REST decision API, MCP tool-call enforcement, A2A message enforcement. |

```yaml
# policy.yaml (the receiving organization's rules)
apiVersion: nexum.dev/v1alpha1
kind: Policy
id: abc-supplier-v1
subjects: [{ organization: xyz.com }]
rules:
  - { action: inventory.read, resource: "supplier://abc/*", effect: allow }
  - { action: quote.create, effect: allow,    conditions: { max_value: 100000 } }
  - { action: quote.create, effect: approval, conditions: { value_above: 100000 } }
  - { action: payment.execute, effect: deny }
delegation: { allowed: [inventory.read, pricing.read], max_depth: 2 }
```

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, formats and
standards mapping.

## Integrations

* **REST:** `POST /v1/authorize` with `Nexum-Grant` / `Nexum-Proof` headers.
* **MCP:** point MCP clients at `POST /mcp/{server}`; tool calls are authorized
  per tool and forwarded only if allowed. See [examples/mcp](examples/mcp).
* **A2A:** `POST /a2a/{agent}` authorizes `SendMessage`, `GetTask`, ... See
  [examples/a2a](examples/a2a).
* **Python / LangGraph:** [examples/python](examples/python/nexum_client.py),
  [examples/langgraph](examples/langgraph/agent.py).

## Principles

1. **Neutral by design** — no required model, framework, cloud, protocol or IdP.
2. **Customer-controlled trust** — organizations keep their own roots of trust.
3. **Local enforcement** — decisions stay inside your environment.
4. **Least privilege** — agents get only what the task needs.
5. **Short-lived authority** — no standing agent privileges.
6. **Delegation only attenuates** — authority never grows downstream.
7. **Deterministic security** — LLMs propose; deterministic systems authorize.
8. **Open standards first** — SPIFFE, JOSE, OAuth, MCP, A2A. Integrate, don't replace.
9. **Auditable by default** — every decision can be reconstructed.
10. **Fail closed** — unknown is denied, not assumed safe.

## CLI

```text
nexum init | doctor | call
nexum gateway start
nexum agents   register | list | inspect [--a2a-card] | revoke
nexum grants   issue | delegate | inspect [--verify] | revoke
nexum trust    list | add | revoke | revoke-key
nexum policies validate | test
nexum approvals list | approve | reject
nexum audit    tail | search | verify
```

## Project

[ROADMAP.md](ROADMAP.md) · [THREAT_MODEL.md](THREAT_MODEL.md) ·
[SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) ·
[CHANGELOG.md](CHANGELOG.md)

Licensed under [Apache-2.0](LICENSE).
