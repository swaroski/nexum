//! Passive discovery: summarize A2A Agent Cards against the local registry.
//!
//! Read-only by design: discovery reports what exists and whether Nexum
//! manages it; it never registers, modifies or calls agents.

use nexum_core::AgentDescriptor;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct Discovered {
    pub source: String,
    pub name: String,
    pub organization: Option<String>,
    pub endpoints: Vec<String>,
    pub skills: Vec<String>,
    pub auth_schemes: Vec<String>,
    /// The registered agent whose endpoint matches, if any.
    pub managed_as: Option<String>,
    pub findings: Vec<&'static str>,
}

/// Summarize an Agent Card (A2A v1.0 `supportedInterfaces`, or v0.3 `url`).
pub fn summarize(source: &str, card: &Value, registry: &[AgentDescriptor]) -> Discovered {
    let s = |v: &Value| v.as_str().map(str::to_owned);
    let mut endpoints: Vec<String> = card["supportedInterfaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| s(&i["url"]))
        .chain(s(&card["url"]))
        .collect();
    endpoints.dedup();
    let skills = card["skills"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| s(&k["id"]).or_else(|| s(&k["name"])))
        .collect();
    let auth_schemes: Vec<String> = card["securitySchemes"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let norm = |u: &str| u.trim_end_matches('/').to_ascii_lowercase();
    let managed_as = registry
        .iter()
        .find(|a| {
            a.endpoint
                .as_deref()
                .is_some_and(|e| endpoints.iter().any(|u| norm(u) == norm(e)))
        })
        .map(|a| a.id.to_string());
    let mut findings = vec![];
    if managed_as.is_none() {
        findings.push("unmanaged: no registered Nexum identity serves this endpoint");
    }
    if auth_schemes.is_empty() {
        findings.push("declares no authentication scheme");
    }
    if endpoints.iter().any(|u| u.starts_with("http://")) {
        findings.push("endpoint without TLS");
    }
    if endpoints.is_empty() {
        findings.push("card lists no endpoint");
    }
    Discovered {
        source: source.to_owned(),
        name: s(&card["name"]).unwrap_or_else(|| "(unnamed)".into()),
        organization: s(&card["provider"]["organization"]),
        endpoints,
        skills,
        auth_schemes,
        managed_as,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn managed_and_unmanaged_cards() {
        let agent: AgentDescriptor = serde_json::from_value(json!({
            "id": "spiffe://abc.com/agents/supplier", "name": "supplier", "organization": "abc.com",
            "description": null, "owner": "ops", "environment": null, "framework": null,
            "capabilities": [], "protocols": ["a2a"], "endpoint": "https://abc.com/a2a/supplier",
            "public_key": null, "status": "active", "metadata": {}, "created_at": "2026-11-01T00:00:00Z"
        }))
        .unwrap();
        let v1 = json!({"name": "Supplier", "provider": {"organization": "ABC"},
            "supportedInterfaces": [{"url": "https://abc.com/a2a/supplier/", "protocolBinding": "JSONRPC"}],
            "securitySchemes": {"bearer": {}}, "skills": [{"id": "quote.create"}]});
        let d = summarize("x", &v1, std::slice::from_ref(&agent));
        assert_eq!(
            d.managed_as.as_deref(),
            Some("spiffe://abc.com/agents/supplier")
        );
        assert!(d.findings.is_empty(), "{:?}", d.findings);

        let v03 = json!({"name": "Shadow", "url": "http://10.0.0.7:9000/a2a"});
        let d = summarize("y", &v03, &[agent]);
        assert_eq!(d.managed_as, None);
        assert_eq!(d.findings.len(), 3);
    }
}
