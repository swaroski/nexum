# A2A: enforce agent-to-agent calls

Nexum treats [A2A](https://a2a-protocol.org) (v1.0 JSON-RPC binding; v0.3
method names accepted) as a transport. The gateway authorizes each A2A
operation and forwards it to the target agent only if allowed.

```yaml
# nexum.yaml
a2a:
  supplier:
    url: http://127.0.0.1:9100/a2a/v1
```

| A2A method | Action |
|---|---|
| `SendMessage` (`message/send`) | `a2a.supplier.message.send` |
| `SendStreamingMessage` (`message/stream`) | `a2a.supplier.message.stream` |
| `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask` | `a2a.supplier.task.{get,list,cancel,subscribe}` |
| `GetExtendedAgentCard` | `a2a.supplier.card.extended` |
| `*TaskPushNotificationConfig` | `a2a.supplier.push_config.manage` |

Unknown methods are rejected. Resource: `a2a://supplier`.

Grant a calling agent the operations it needs:

```bash
nexum grants issue --sub spiffe://xyz.com/agents/procurement --holder procurement.key.json \
  --cap 'a2a.supplier.message.*' --cap a2a.supplier.task.get \
  --res 'a2a://supplier' --aud abc.com
```

Discovery uses A2A Agent Cards rather than a Nexum-specific format:

```bash
nexum agents register --id spiffe://abc.com/agents/supplier --name supplier \
  --protocol a2a --endpoint https://abc.com/a2a/supplier --capability quote.create
nexum agents inspect spiffe://abc.com/agents/supplier --a2a-card
```
