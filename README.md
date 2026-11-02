<div align="center">

# Nexum

### The open trust & authorization layer for AI agents

**Know who every agent is, who it acts for, what it was delegated, and stop everything else.**

[![CI](https://github.com/swaroski/nexum/actions/workflows/ci.yml/badge.svg)](https://github.com/swaroski/nexum/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![Status: alpha](https://img.shields.io/badge/status-v0.1%20alpha-yellow.svg)](ROADMAP.md)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#security-model)

[Quick start](#-quick-start) ·
[Use cases](#-use-cases) ·
[How it works](#-how-it-works) ·
[Demo](#-the-cross-company-demo) ·
[Architecture](ARCHITECTURE.md) ·
[Threat model](THREAT_MODEL.md)

</div>

---

## The problem

AI agents now call APIs, run tools, move money and talk to *other companies'*
agents. Most of them do it with a long-lived API key or a forwarded user token,
and the only thing between a prompt injection and a $50,000 refund is the
model's judgment.

```mermaid
flowchart LR
    subgraph today["😬 Today"]
        direction LR
        U1["👤 Jane"] -->|"full OAuth token"| A1["🤖 Agent"]
        A1 -->|"same token, forwarded"| B1["🤖 Sub-agent"]
        B1 -->|"static API key"| T1[("💳 Payments API")]
        A1 -.->|"shared secret"| X1["🏢 Partner's agent"]
    end
```

Nobody can answer the questions that matter: *Which agent did this? On whose
behalf? Who gave it that power? Was it allowed to pass it on? Can we turn it
off right now? Can the partner verify any of it without trusting us blindly?*

## What Nexum does

Nexum is a small, fast **gateway** that sits in front of your tools, APIs and
agents. Every request carries **cryptographic proof of delegated authority**,
and the gateway decides deterministically, inside your own environment:

```mermaid
flowchart LR
    subgraph withnx["✅ With Nexum"]
        direction LR
        U2["👤 Jane"] -->|"delegates<br/>quote.create ≤ $100k<br/>15 min"| A2["🤖 Agent"]
        A2 -->|"delegates<br/>inventory.read only"| B2["🤖 Sub-agent"]
        B2 -->|"signed chain<br/>+ fresh proof"| G{{"🛡️ Nexum gateway"}}
        G -->|"ALLOW"| T2[("📦 Inventory API")]
        G -.->|"DENY NX-4032"| T3[("💳 Payments API")]
        G -->|"every decision"| L[("🧾 Tamper-evident audit")]
    end
```

| | |
|---|---|
| 🪪 **Agent identity** | Every agent gets its own [SPIFFE](https://spiffe.io) ID, separate from the human using it. |
| 🔗 **Delegation that only shrinks** | Each hop can only *narrow* capabilities, resources, value limits, audience and lifetime. Enforced cryptographically. |
| 🔑 **No bearer tokens** | Each request carries a one-time signature by the agent's key over the exact body. Stolen grants and replayed requests fail. |
| 🤝 **Cross-company trust** | A partner verifies your agents with *your* public key under *their* policy. No shared secrets, and no vendor in the middle. |
| ⚖️ **Three outcomes** | `ALLOW`, `DENY`, or `REQUIRE_APPROVAL` with single-use human approvals bound to the exact request. |
| ⛔ **Instant revocation** | Kill an agent, a grant, a key or a whole partner relationship. Every descendant grant dies with it. |
| 🧾 **Audit you can verify** | One hash-chained event per decision. `nexum audit verify` detects edits, deletions and reordering. |
| 🔌 **Protocol adapters** | REST decision API, **MCP** tool-call enforcement, **A2A** message enforcement. |

> **LLMs propose. Deterministic systems authorize.** No prompt, model output or
> agent message can change what an agent is allowed to do.

## 🎯 Use cases

<table>
<tr>
<td width="50%" valign="top">

### 💸 Customer-support refunds with limits
A support agent can refund up to **$500** on its own. Above that, Nexum returns
`REQUIRE_APPROVAL`, a human approves *that exact refund*, and the agent retries.
A prompt-injected "refund $50,000" never reaches the payments API.

</td>
<td width="50%" valign="top">

### 🏢 Agent-to-agent across companies
Your procurement agent asks a supplier's agent for prices and quotes. The
supplier verifies your agent cryptographically, applies *its own* policy, and
can cut you off with one command. → [demo](#-the-cross-company-demo)

</td>
</tr>
<tr>
<td valign="top">

### 🧰 An MCP tool firewall
Put Nexum in front of MCP servers. Each `tools/call` maps to a capability:
`read_file` is allowed, `delete_repo` is denied, `deploy_prod` needs approval.
Works with any MCP client that can sign requests.

</td>
<td valign="top">

### 🪆 Safe sub-agent orchestration
An orchestrator spawns workers and hands each a **narrower** grant that is
scoped to one task, one resource prefix and five minutes. A worker can't
escalate, re-delegate beyond its depth, or outlive its parent.

</td>
</tr>
<tr>
<td valign="top">

### 🏥 Purpose-bound data access
Grants carry a `purpose` (e.g. `claims-review`) and an actor (`dr.lee@clinic`).
Policy can require both, and the audit log records them, which is the trail
regulated teams need for HIPAA, SOX and GDPR reviews.

</td>
<td valign="top">

### ⏱️ Zero standing privilege
Long-running autonomous agents hold **no permanent permissions**. Each task
gets a short-lived grant, which expires or is revoked when the task ends. If an
agent's credentials leak, they are worthless without its key.

</td>
</tr>
<tr>
<td valign="top">

### 🌐 Multi-vendor agent fleets
A LangGraph agent on AWS calls a Mastra agent on Azure that uses an MCP tool on
GCP. Nexum sees only identities, delegations, actions and policy, whatever the
framework, cloud or model.

</td>
<td valign="top">

### 🔍 Security review & incident response
`nexum policies test` answers "would this be allowed?" before you deploy.
`nexum audit search` answers "what did this agent do, and for whom?" after an
incident, from a log you can prove hasn't been altered.

</td>
</tr>
</table>

## ⚡ Quick start

```bash
cargo install --git https://github.com/swaroski/nexum nexum     # or use Docker, below

nexum init --domain example.com        # config, trust store, starter policy, org key
nexum agents register --id spiffe://example.com/agents/support-bot --name support-bot
nexum grants issue --sub spiffe://example.com/agents/support-bot \
  --holder .nexum/keys/support-bot.key.json \
  --cap refund.create --res 'app://orders/*' --aud example.com --out bot.jwt
nexum gateway start &

nexum call --grant bot.jwt --key .nexum/keys/support-bot.key.json \
  --action refund.create --resource app://orders/42 --value 1700
```

```text
APPROVAL REQUIRED NX-4002

  Agent:      spiffe://example.com/agents/support-bot
  Requested:  refund.create  app://orders/42
  Value:      1700
  Reason:     Policy requires human approval for this action.
  Policy:     example.com-default / refund-approval
  Approval:   01a1999a-6988-77d1-8883-a360a450ad5e
```

<details>
<summary><b>🐳 Run with Docker</b></summary>

```bash
NEXUM_DOMAIN=example.com docker compose -f deploy/docker/docker-compose.yml up -d
curl localhost:8080/healthz                                   # ok
docker compose -f deploy/docker/docker-compose.yml exec nexum nexum doctor
```

The container runs as a non-root user with a read-only root filesystem.
Config, keys, state and audit live in the `nexum-data` volume.

</details>

<details>
<summary><b>☸️ Kubernetes</b></summary>

A minimal manifest is in [`deploy/kubernetes/nexum.yaml`](deploy/kubernetes/nexum.yaml).
It is single-replica on purpose in v0.1 (replay cache and state are per instance).

</details>

## 🔍 How it works

### Every request, eight deterministic checks

```mermaid
flowchart TD
    REQ(["📨 Request<br/>Nexum-Grant · Nexum-Proof · body"]) --> N
    N["1 · Normalize<br/>REST / MCP / A2A → action, resource, value"] --> C
    C{"2 · Delegation chain<br/>signed · attenuated · unexpired<br/>audience · not revoked"} -->|fail| D
    C --> P{"3 · Proof of possession<br/>holder key · this body · this gateway<br/>fresh · single use"}
    P -->|fail| D
    P --> A{"4 · Chain authority<br/>action ∈ grant · resource ∈ grant<br/>value ≤ limit"}
    A -->|fail| D
    A --> T{"5 · Trust<br/>does the receiving org accept<br/>this from the issuing org?"}
    T -->|fail| D
    T --> POL{"6 · Policy<br/>built-in or OPA / Cedar / …"}
    POL -->|deny| D
    POL -->|approval| AP{"7 · Approval<br/>matching & unused?"}
    POL -->|allow| OK
    AP -->|no| HOLD(["⏸️ REQUIRE_APPROVAL<br/>approval id issued"])
    AP -->|yes| OK(["✅ ALLOW"])
    D(["⛔ DENY + reason code"])
    OK --> AU[("8 · Hash-chained audit<br/>write fails → DENY")]
    D --> AU
    HOLD --> AU

    classDef deny fill:#fde2e1,stroke:#d93025,color:#5c0b07
    classDef allow fill:#dff5e3,stroke:#1e8e3e,color:#0b3d1a
    classDef hold fill:#fff4d6,stroke:#f9ab00,color:#5c4400
    class D deny
    class OK allow
    class HOLD hold
```

Anything unknown, unverifiable or unavailable is a **DENY** with a stable
reason code (`NX-xxxx`). There is no "warn and continue" path.

### Delegation only ever narrows

```mermaid
flowchart LR
    H["👤 jane@xyz.com"] ==>|"issues root grant"| A
    A["🤖 procurement<br/>━━━━━━━━━━━━<br/>inventory.read<br/>pricing.read<br/>quote.create<br/>15 min · depth 1"]
    A ==>|"delegates subset"| B["🤖 inventory-checker<br/>━━━━━━━━━━━━<br/>inventory.read<br/>5 min · depth 0"]
    B -.->|"✗ cannot add payment.execute"| X1["💳"]
    B -.->|"✗ cannot delegate further"| X2["🤖"]
    B -.->|"✗ cannot outlive parent"| X3["⏱️"]

    classDef human fill:#e8f0fe,stroke:#1a73e8,color:#0b2a5c
    classDef agent fill:#f3e8fd,stroke:#8430ce,color:#3a0f63
    classDef blocked fill:#fde2e1,stroke:#d93025,color:#5c0b07
    class H human
    class A,B agent
    class X1,X2,X3 blocked
```

`authority(child) ⊆ authority(parent)`, checked on every hop, every request,
and property-tested.

### Cross-company trust without a middleman

```mermaid
sequenceDiagram
    autonumber
    actor Jane as 👤 Jane (XYZ)
    participant XA as 🤖 XYZ procurement agent
    participant GW as 🛡️ ABC's Nexum gateway
    participant API as 📦 ABC supplier API
    actor CFO as 👤 ABC approver

    Note over Jane,GW: One-time: ABC adds XYZ's public key<br/>and allows inventory.read, pricing.read, quote.create
    Jane->>XA: root grant signed by XYZ (15 min, acting for Jane)
    XA->>GW: inventory.read + grant chain + fresh proof
    GW->>GW: verify XYZ signature, attenuation, proof, ABC trust, ABC policy
    GW->>API: ✅ ALLOW → forward
    XA->>GW: quote.create, value $250,000
    GW-->>XA: ⏸️ REQUIRE_APPROVAL (approval id)
    CFO->>GW: nexum approvals approve {id}
    XA->>GW: retry with Nexum-Approval: {id}
    GW->>API: ✅ ALLOW (approval consumed, single use)
    Note over GW: ABC revokes trust in XYZ → every XYZ grant denied instantly
```

XYZ never shares a secret with ABC, and ABC never trusts a third party. Each
organization stays its own root of trust.

## 🎬 The cross-company demo

```bash
git clone https://github.com/swaroski/nexum && cd nexum
./examples/cross-company/demo.sh
```

Two organizations are initialized from scratch. ABC's gateway starts, and
XYZ's agents exercise it:

| # | Who | Asks for | Result | Why |
|---|---|---|---|---|
| 1 | procurement | `inventory.read` | ✅ `ALLOW` | in grant, trusted, policy allows |
| 2 | inventory-checker (delegated) | `inventory.read` | ✅ `ALLOW` | valid attenuated delegation |
| 3 | inventory-checker | `payment.execute` | ⛔ `DENY NX-4032` | not present in the delegation chain |
| — | inventory-checker | *mint itself* `payment.execute` | ⛔ refused | `NX-1015` parent forbids further delegation |
| 4 | procurement | `quote.create` $250,000 | ⏸️ `REQUIRE_APPROVAL` | policy: approval above $100k |
| 5 | procurement + approval | same quote | ✅ `ALLOW NX-4003` | approved, consumed once |
| 6 | procurement | anything | ⛔ `DENY NX-3003` | ABC revoked trust in XYZ |

```text
$ nexum audit verify
audit chain intact: 6 events
```

## 🔌 Integrations

| Surface | Endpoint | Status |
|---|---|---|
| **REST decision API** | `POST /v1/authorize` | ✅ alpha |
| **MCP** (spec 2026-07-28, Streamable HTTP) | `POST /mcp/{server}` | 🧪 experimental · [guide](examples/mcp) |
| **A2A** (v1.0 JSON-RPC, v0.3 aliases) | `POST /a2a/{agent}` | 🧪 experimental · [guide](examples/a2a) |
| **Python client** | [`nexum_client.py`](examples/python/nexum_client.py) | 🧪 experimental |
| **LangGraph** | [`examples/langgraph`](examples/langgraph/agent.py) | 🧪 experimental |
| OPA · Cedar · Cerbos · SpiceDB | `PolicyDecisionPoint` trait | 🗺️ [roadmap](ROADMAP.md) |
| SPIRE · Entra · Okta · AWS · GCP identity | identity adapters | 🗺️ [roadmap](ROADMAP.md) |

<details>
<summary><b>Example policy</b></summary>

```yaml
apiVersion: nexum.dev/v1alpha1
kind: Policy
id: abc-supplier-v1
subjects: [{ organization: xyz.com }]
rules:
  - { action: inventory.read,  resource: "supplier://abc/*", effect: allow }
  - { action: quote.create,    effect: allow,    conditions: { max_value: 100000 } }
  - { action: quote.create,    effect: approval, conditions: { value_above: 100000 } }
  - { action: payment.execute, effect: deny }
delegation:
  allowed: [inventory.read, pricing.read]   # what sub-agents may exercise
  max_depth: 2
```

Deny-overrides, default deny, unknown fields rejected.

</details>

<details>
<summary><b>Example trust store</b></summary>

```yaml
apiVersion: nexum.dev/v1alpha1
trust_domains:
  xyz.com:
    issuer: https://identity.xyz.com
    keys: [{ kty: OKP, crv: Ed25519, x: "…", kid: "lCLq5SsW…" }]   # standard JWKS
    allow: [inventory.read, pricing.read, quote.create]
    deny:  [payment.execute, customer.export]
    max_grant_ttl_seconds: 3600
```

</details>

## 🧭 What Nexum is, and isn't

| ✅ Nexum is | ❌ Nexum is not |
|---|---|
| A local enforcement gateway + CLI | A hosted service you must trust |
| Identity, delegation, trust, policy, audit | An LLM, agent framework or prompt tool |
| Built on SPIFFE, JOSE, OAuth `act`/`cnf`, MCP, A2A | A new PKI, IdP or crypto scheme |
| An adapter host for OPA, Cedar, your PDP | A replacement for your authorization stack |
| Cloud-, model-, framework-neutral | Tied to any vendor |

## Security model

* **Ed25519 only** (`alg: EdDSA`), strict verification; `none`/HMAC/key-URL headers rejected.
* **Holder-of-key grants + per-request proofs** bound to body, grant and gateway; single use.
* **Fail closed** on every error, including policy, state and audit failures.
* **No credentials forwarded** upstream; no tokens or payloads in logs or audit.
* `#![forbid(unsafe_code)]` everywhere; attack-named negative tests and property tests.

Read the full [threat model](THREAT_MODEL.md) (24 threats, mitigations and
residual risks). Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

> **Status:** v0.1, `nexum.dev/v1alpha1`. Not yet independently
> security-reviewed. Don't make it your only control for high-impact actions yet.

## 🛠️ CLI

```text
nexum init | doctor | call
nexum gateway   start
nexum agents    register | list | inspect [--a2a-card] | revoke
nexum grants    issue | delegate | inspect [--verify] | revoke
nexum trust     list | add | revoke | revoke-key
nexum policies  validate | test
nexum approvals list | approve | reject
nexum audit     tail | search | verify
```

## Principles

**Neutral by design** · **Customer-controlled trust** · **Local enforcement** ·
**Least privilege** · **Short-lived authority** · **Delegation only attenuates** ·
**Deterministic security** · **Open standards first** · **Auditable by default** ·
**Fail closed**

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md),
[ARCHITECTURE.md](ARCHITECTURE.md) and the [roadmap](ROADMAP.md).

<div align="center">

Licensed under [Apache-2.0](LICENSE)

</div>
