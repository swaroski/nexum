//! The browser playground: Nexum's decision pipeline in WebAssembly.
//!
//! [`evaluate_json`] takes a scenario (the `EvalSuite` scenario DSL), the
//! receiving organization's trust relationship and policy, mints a real
//! signed grant chain and proof with throwaway keys, and decides it with
//! `nexum_sim::decide`, which is held to the gateway's results on the official
//! eval suite. Nothing leaves the browser.

#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]

#[cfg(target_arch = "wasm32")]
mod wasm;

use nexum_core::{Capability, TrustDomain};
use nexum_grant::{KeyPair, TrustDomainConfig, TrustStore};
use nexum_policy::PolicySet;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    /// The receiving gateway's trust domain.
    audience: String,
    /// The calling organization.
    org: TrustDomain,
    trust: TrustInput,
    /// Built-in policy YAML.
    policy: String,
    scenario: nexum_sim::Scenario,
    /// Unix seconds.
    now: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustInput {
    #[serde(default)]
    allow: Vec<Capability>,
    #[serde(default)]
    deny: Vec<Capability>,
    #[serde(default = "default_ttl")]
    max_grant_ttl_seconds: i64,
    /// Simulate "this organization is not in the trust store".
    #[serde(default)]
    untrusted: bool,
}

fn default_ttl() -> i64 {
    nexum_grant::DEFAULT_MAX_GRANT_TTL_SECONDS
}

/// Evaluate one playground request. Input and output are JSON; errors are
/// returned as `{"error": "..."}` rather than panics.
pub fn evaluate_json(input: &str) -> String {
    match evaluate(input) {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "error": e }).to_string(),
    }
}

fn evaluate(input: &str) -> Result<Value, String> {
    let i: Input = serde_json::from_str(input).map_err(|e| format!("input: {e}"))?;
    let policy = PolicySet::from_yaml(&i.policy).map_err(|e| format!("policy: {e}"))?;
    let key = KeyPair::generate();
    let issuer = format!("https://identity.{}", i.org.as_str());
    let mut trust = TrustStore {
        api_version: nexum_core::API_VERSION.into(),
        ..Default::default()
    };
    if !i.trust.untrusted {
        trust.trust_domains.insert(
            i.org.clone(),
            TrustDomainConfig {
                issuer: issuer.clone(),
                keys: vec![key.public_jwk()],
                allow: i.trust.allow,
                deny: i.trust.deny,
                max_grant_ttl_seconds: i.trust.max_grant_ttl_seconds,
            },
        );
    }
    let m = nexum_sim::mint(&i.scenario, &i.org, &issuer, &key, &i.audience, i.now)
        .map_err(|e| format!("scenario: {e:#}"))?;
    let grants: Vec<Value> = m
        .chain
        .iter()
        .filter_map(|t| nexum_grant::decode_unverified(t).ok())
        .map(|c| {
            json!({
                "sub": c.sub, "act": c.act.map(|a| a.sub), "cap": c.cap, "res": c.res,
                "dcap": c.dcap, "max_depth": c.mdd, "max_value": c.max_value,
                "purpose": c.purpose, "ttl_seconds": c.exp - c.iat,
            })
        })
        .collect();
    let d = nexum_sim::decide(&trust, &policy, &i.audience, &m, i.now);
    Ok(
        json!({ "decision": d, "grants": grants, "token_bytes": m.chain.iter().map(String::len).sum::<usize>() }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(scenario: Value, trust: Value) -> Value {
        let input = json!({
            "audience": "abc.com", "org": "xyz.com", "trust": trust, "now": 1_800_000_000,
            "policy": "apiVersion: nexum.dev/v1alpha1\nkind: Policy\nid: p\nsubjects: [{organization: xyz.com}]\nrules:\n  - {id: read, action: inventory.read, effect: allow}\n",
            "scenario": scenario,
        });
        serde_json::from_str(&evaluate_json(&input.to_string())).unwrap_or_default()
    }

    #[test]
    fn worker_escalation_and_attacks() {
        let grants = json!([
            {"sub": "spiffe://xyz.com/agents/procurement", "cap": ["inventory.read", "pricing.read"], "res": ["supplier://abc/*"], "dcap": ["inventory.read"], "max_depth": 1},
            {"sub": "spiffe://xyz.com/agents/worker", "cap": ["inventory.read"]}
        ]);
        let trust = json!({"allow": ["inventory.read", "pricing.read", "payment.execute"]});
        let req = |action: &str, attack: Value| {
            json!({"name": "t", "expect": "ALLOW", "grants": grants, "attack": attack,
                   "request": {"action": action, "resource": "supplier://abc/x"}})
        };
        let d = &run(req("inventory.read", Value::Null), trust.clone())["decision"];
        assert_eq!(
            (d["outcome"].as_str(), d["code"].as_str()),
            (Some("ALLOW"), Some("NX-4001"))
        );
        let d = &run(req("payment.execute", Value::Null), trust.clone())["decision"];
        assert_eq!(d["code"], "NX-4032");
        assert_eq!(d["checks"][3]["status"], "FAIL");
        let d = &run(req("inventory.read", json!("replay")), trust.clone())["decision"];
        assert_eq!(d["code"], "NX-2004");
        let d = &run(
            req("inventory.read", Value::Null),
            json!({"untrusted": true}),
        )["decision"];
        assert_eq!(d["code"], "NX-1006");
        assert!(run(json!({"bad": 1}), trust)["error"].is_string());
    }
}
