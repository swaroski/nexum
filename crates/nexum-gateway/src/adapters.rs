//! Protocol adapters: translate a wire message into a [`Normalized`] action.
//!
//! Adapters only *describe* what a message would do. They never decide. Every
//! message is authorized, including discovery and listing calls: unknown or
//! unmapped operations get a derived capability that policy must allow.

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use nexum_core::{AgentDescriptor, Capability, ReasonCode, ResourcePattern};
use serde_json::Value;

use crate::authorizer::Normalized;
use crate::config::{McpServer, Upstream};

pub trait ProtocolAdapter: Send + Sync {
    const PROTOCOL: &'static str;

    /// Upstream URL for a named target, if configured.
    fn upstream(&self, target: &str) -> Option<&str>;

    fn normalize(
        &self,
        target: &str,
        headers: &HeaderMap,
        message: &Value,
    ) -> Result<Normalized, ReasonCode>;
}

fn cap(s: &str) -> Result<Capability, ReasonCode> {
    Capability::parse(s).map_err(|_| ReasonCode::InvalidRequest)
}

fn res(s: &str) -> Result<ResourcePattern, ReasonCode> {
    ResourcePattern::parse(s).map_err(|_| ReasonCode::InvalidRequest)
}

/// A single JSON-RPC 2.0 request or notification. Batches are rejected:
/// MCP removed them, and authorizing a batch as one action is unsound.
fn jsonrpc_method(message: &Value) -> Result<&str, ReasonCode> {
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(ReasonCode::InvalidRequest);
    }
    message
        .get("method")
        .and_then(Value::as_str)
        .ok_or(ReasonCode::InvalidRequest)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// MCP (2026-07-28, Streamable HTTP). `tools/call` maps to
/// `mcp.<server>.tool.<name>` (or the configured action); every other method
/// maps to `mcp.<server>.rpc.<method with / replaced by .>`.
#[derive(Debug)]
pub struct McpAdapter {
    pub servers: BTreeMap<String, McpServer>,
}

impl ProtocolAdapter for McpAdapter {
    const PROTOCOL: &'static str = "mcp";

    fn upstream(&self, target: &str) -> Option<&str> {
        self.servers.get(target).map(|s| s.url.as_str())
    }

    fn normalize(
        &self,
        server: &str,
        headers: &HeaderMap,
        msg: &Value,
    ) -> Result<Normalized, ReasonCode> {
        let cfg = self.servers.get(server).ok_or(ReasonCode::InvalidRequest)?;
        let method = jsonrpc_method(msg)?;
        // MCP routing headers must agree with the body, or an intermediary
        // could route/authorize on one value while the server executes another.
        if header(headers, "mcp-method").is_some_and(|h| h != method) {
            return Err(ReasonCode::InvalidRequest);
        }
        let mut attributes = BTreeMap::from([("mcp.method".into(), Value::from(method))]);

        if method != "tools/call" {
            return Ok(Normalized {
                action: cap(&format!("mcp.{server}.rpc.{}", method.replace('/', ".")))?,
                resource: res(&format!("mcp://{server}"))?,
                value: None,
                protocol: Self::PROTOCOL,
                attributes,
            });
        }

        let params = msg.get("params").ok_or(ReasonCode::InvalidRequest)?;
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or(ReasonCode::InvalidRequest)?;
        if header(headers, "mcp-name").is_some_and(|h| h != tool) {
            return Err(ReasonCode::InvalidRequest);
        }
        let mapping = cfg.tools.get(tool);
        let action = match mapping.and_then(|m| m.action.clone()) {
            Some(a) => a,
            None => cap(&format!("mcp.{server}.tool.{tool}"))?,
        };
        let value = match mapping.and_then(|m| m.value_argument.as_deref()) {
            Some(arg) => match params.get("arguments").and_then(|a| a.get(arg)) {
                None => None,
                Some(v) => Some(v.as_u64().ok_or(ReasonCode::InvalidRequest)?),
            },
            None => None,
        };
        attributes.insert("mcp.tool".into(), Value::from(tool));
        Ok(Normalized {
            action,
            resource: res(&format!("mcp://{server}/tools/{tool}"))?,
            value,
            protocol: Self::PROTOCOL,
            attributes,
        })
    }
}

/// A2A v1.0 JSON-RPC binding (v0.3 method names accepted as aliases).
#[derive(Debug)]
pub struct A2aAdapter {
    pub agents: BTreeMap<String, Upstream>,
}

fn a2a_operation(method: &str) -> Option<&'static str> {
    Some(match method {
        "SendMessage" | "message/send" => "message.send",
        "SendStreamingMessage" | "message/stream" => "message.stream",
        "GetTask" | "tasks/get" => "task.get",
        "ListTasks" | "tasks/list" => "task.list",
        "CancelTask" | "tasks/cancel" => "task.cancel",
        "SubscribeToTask" | "tasks/resubscribe" => "task.subscribe",
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => "card.extended",
        "CreateTaskPushNotificationConfig"
        | "GetTaskPushNotificationConfig"
        | "ListTaskPushNotificationConfig"
        | "DeleteTaskPushNotificationConfig"
        | "tasks/pushNotificationConfig/set"
        | "tasks/pushNotificationConfig/get"
        | "tasks/pushNotificationConfig/list"
        | "tasks/pushNotificationConfig/delete" => "push_config.manage",
        _ => return None,
    })
}

impl ProtocolAdapter for A2aAdapter {
    const PROTOCOL: &'static str = "a2a";

    fn upstream(&self, target: &str) -> Option<&str> {
        self.agents.get(target).map(|a| a.url.as_str())
    }

    fn normalize(&self, agent: &str, _: &HeaderMap, msg: &Value) -> Result<Normalized, ReasonCode> {
        if !self.agents.contains_key(agent) {
            return Err(ReasonCode::InvalidRequest);
        }
        let method = jsonrpc_method(msg)?;
        let op = a2a_operation(method).ok_or(ReasonCode::InvalidRequest)?;
        Ok(Normalized {
            action: cap(&format!("a2a.{agent}.{op}"))?,
            resource: res(&format!("a2a://{agent}"))?,
            value: None,
            protocol: Self::PROTOCOL,
            attributes: BTreeMap::from([("a2a.method".into(), Value::from(method))]),
        })
    }
}

/// Render a registry entry as an A2A v1.0 Agent Card. Nexum does not define
/// its own discovery document; A2A peers discover agents through this.
pub fn agent_card(a: &AgentDescriptor) -> Value {
    let interfaces: Vec<Value> = a
        .endpoint
        .iter()
        .filter(|_| a.protocols.iter().any(|p| p == "a2a"))
        .map(|url| serde_json::json!({"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}))
        .collect();
    serde_json::json!({
        "name": a.name,
        "description": a.description.clone().unwrap_or_default(),
        "version": "1.0.0",
        "provider": {"organization": a.organization.as_str()},
        "supportedInterfaces": interfaces,
        "capabilities": {},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": a.capabilities.iter().map(|c| serde_json::json!({
            "id": c.as_str(), "name": c.as_str(), "description": "", "tags": ["nexum-capability"]
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ToolMapping;
    use serde_json::json;

    fn mcp() -> McpAdapter {
        McpAdapter {
            servers: BTreeMap::from([(
                "payments".into(),
                McpServer {
                    url: "http://x".into(),
                    tools: BTreeMap::from([(
                        "refund".into(),
                        ToolMapping {
                            action: Some(Capability::parse("refund.create").unwrap()),
                            value_argument: Some("amount".into()),
                        },
                    )]),
                },
            )]),
        }
    }

    fn call(name: &str, args: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
    }

    #[test]
    fn mcp_tool_calls() {
        let h = HeaderMap::new();
        let n = mcp()
            .normalize("payments", &h, &call("refund", json!({"amount": 1700})))
            .unwrap();
        assert_eq!(n.action.as_str(), "refund.create");
        assert_eq!(n.value, Some(1700));
        assert_eq!(n.resource.as_str(), "mcp://payments/tools/refund");

        let n = mcp()
            .normalize("payments", &h, &call("lookup", json!({})))
            .unwrap();
        assert_eq!(n.action.as_str(), "mcp.payments.tool.lookup");

        let n = mcp()
            .normalize(
                "payments",
                &h,
                &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            )
            .unwrap();
        assert_eq!(n.action.as_str(), "mcp.payments.rpc.tools.list");
    }

    #[test]
    fn mcp_rejects_ambiguous_messages() {
        let h = HeaderMap::new();
        let a = mcp();
        // Negative or non-integer value.
        assert!(
            a.normalize("payments", &h, &call("refund", json!({"amount": -5})))
                .is_err()
        );
        assert!(
            a.normalize("payments", &h, &call("refund", json!({"amount": "1"})))
                .is_err()
        );
        // Batches, missing version, unknown server, weird tool names.
        assert!(
            a.normalize("payments", &h, &json!([call("refund", json!({}))]))
                .is_err()
        );
        assert!(
            a.normalize("payments", &h, &json!({"method": "tools/list"}))
                .is_err()
        );
        assert!(
            a.normalize("other", &h, &call("refund", json!({})))
                .is_err()
        );
        assert!(
            a.normalize("payments", &h, &call("a b", json!({})))
                .is_err()
        );
        // Header/body disagreement.
        let mut h = HeaderMap::new();
        h.insert("mcp-name", "lookup".parse().unwrap());
        assert!(
            a.normalize("payments", &h, &call("refund", json!({"amount": 1})))
                .is_err()
        );
    }

    #[test]
    fn a2a_methods() {
        let a = A2aAdapter {
            agents: BTreeMap::from([(
                "supplier".into(),
                Upstream {
                    url: "http://x".into(),
                },
            )]),
        };
        let h = HeaderMap::new();
        for m in ["SendMessage", "message/send"] {
            let n = a
                .normalize(
                    "supplier",
                    &h,
                    &json!({"jsonrpc": "2.0", "id": 1, "method": m}),
                )
                .unwrap();
            assert_eq!(n.action.as_str(), "a2a.supplier.message.send");
        }
        assert!(
            a.normalize(
                "supplier",
                &h,
                &json!({"jsonrpc": "2.0", "id": 1, "method": "Evil"})
            )
            .is_err()
        );
    }
}
