# MCP: enforce tool calls

The gateway sits in front of an MCP server (Streamable HTTP, spec
`2026-07-28`) and authorizes **every** JSON-RPC message before forwarding it.

```text
MCP client ──POST /mcp/payments──▶ nexum ──(if ALLOW)──▶ http://payments:9000/mcp
            Nexum-Grant, Nexum-Proof        strips Nexum-* and Authorization
```

Add to `nexum.yaml`:

```yaml
mcp:
  payments:
    url: http://127.0.0.1:9000/mcp
    tools:
      refund:
        action: refund.create       # capability required to call this tool
        value_argument: amount      # exposed to policy as `value`
```

| Message | Action | Resource |
|---|---|---|
| `tools/call` `refund` | `refund.create` (mapped) | `mcp://payments/tools/refund` |
| `tools/call` `lookup` (unmapped) | `mcp.payments.tool.lookup` | `mcp://payments/tools/lookup` |
| `tools/list` | `mcp.payments.rpc.tools.list` | `mcp://payments` |
| `server/discover` | `mcp.payments.rpc.server.discover` | `mcp://payments` |

Policy then decides, e.g.:

```yaml
rules:
  - { action: mcp.payments.rpc.*, effect: allow }        # discovery/listing
  - { action: refund.create, effect: allow,    conditions: { max_value: 500 } }
  - { action: refund.create, effect: approval, conditions: { value_above: 500 } }
```

A $1,700 refund returns HTTP 202 with a JSON-RPC error (`code: -32002`)
carrying the approval id; the MCP server is never called. Denials return 403
with `code: -32001`. If the request carries `Mcp-Method` / `Mcp-Name` headers,
they must match the body.

Each request needs a fresh proof over the exact body, so the MCP client must
sign requests — wrap its HTTP transport with
[`nexum_client.NexumClient.post`](../python/nexum_client.py) (Python) or
`nexum_grant::create_proof` (Rust). The end-to-end test
`crates/nexum-gateway/tests/cross_company.rs::mcp_tool_calls_are_enforced_and_forwarded`
runs this against a mock MCP server.
