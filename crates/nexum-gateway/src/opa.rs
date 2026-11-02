//! Open Policy Agent as the policy decision point.
//!
//! POSTs `{"input": <AuthorizationRequest>}` to an OPA data API rule and
//! accepts either a boolean (`true` = ALLOW) or
//! `{"outcome": "ALLOW" | "DENY" | "REQUIRE_APPROVAL", "policy_id"?, "rule_id"?}`.
//! Like the built-in engine it runs after chain authority and trust, so it
//! can only narrow. Anything else (HTTP error, timeout, undefined rule,
//! unexpected shape) is an error, which the gateway turns into DENY NX-5002:
//! a mistyped rule path must show up as a failure, not as a quiet default deny.

use std::time::Duration;

use async_trait::async_trait;
use nexum_core::{AuthorizationRequest, Outcome, PolicyDecisionPoint, PolicyResult, ReasonCode};
use serde::Deserialize;

/// OPA responses larger than this are rejected.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct OpaPdp {
    pub url: String,
    pub http: reqwest::Client,
}

impl OpaPdp {
    pub fn new(url: String, timeout: Duration) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { url, http })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Detailed {
    outcome: Outcome,
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    rule_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OpaResult {
    Bool(bool),
    Detailed(Detailed),
}

#[derive(Deserialize)]
struct OpaResponse {
    /// Absent when the rule is undefined.
    result: Option<OpaResult>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Map an OPA data API response body to a policy result.
pub fn parse_response(body: &[u8]) -> Result<PolicyResult, BoxError> {
    let resp: OpaResponse = serde_json::from_slice(body)?;
    let (outcome, policy_id, rule_id) = match resp.result {
        None => return Err("OPA rule is undefined (check the policy url and package)".into()),
        Some(OpaResult::Bool(b)) => (if b { Outcome::Allow } else { Outcome::Deny }, None, None),
        Some(OpaResult::Detailed(d)) => (d.outcome, d.policy_id, d.rule_id),
    };
    let reason = match outcome {
        Outcome::Allow => ReasonCode::PolicyAllow,
        Outcome::Deny => ReasonCode::PolicyDeny,
        Outcome::RequireApproval => ReasonCode::ApprovalRequired,
    };
    Ok(PolicyResult {
        outcome,
        policy_id: policy_id.or_else(|| Some("opa".into())),
        rule_id,
        reason,
    })
}

#[async_trait]
impl PolicyDecisionPoint for OpaPdp {
    async fn evaluate(&self, request: &AuthorizationRequest) -> Result<PolicyResult, BoxError> {
        let resp = self
            .http
            .post(&self.url)
            .json(&serde_json::json!({ "input": request }))
            .send()
            .await?;
        // Only 200 is an answer; redirects (never followed) and errors fail closed.
        if resp.status() != reqwest::StatusCode::OK {
            return Err(format!("OPA returned HTTP {}", resp.status()).into());
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err("OPA response too large".into());
        }
        let body = resp.bytes().await?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err("OPA response too large".into());
        }
        parse_response(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses() {
        let ok = |b: &str| parse_response(b.as_bytes()).map(|r| (r.outcome, r.reason));
        assert_eq!(
            ok(r#"{"result": true}"#).ok(),
            Some((Outcome::Allow, ReasonCode::PolicyAllow))
        );
        assert_eq!(
            ok(r#"{"result": false}"#).ok(),
            Some((Outcome::Deny, ReasonCode::PolicyDeny))
        );
        let r = parse_response(
            br#"{"result": {"outcome": "REQUIRE_APPROVAL", "policy_id": "p", "rule_id": "big"}}"#,
        )
        .unwrap();
        assert_eq!(
            (r.outcome, r.policy_id.as_deref(), r.rule_id.as_deref()),
            (Outcome::RequireApproval, Some("p"), Some("big"))
        );
        // Undefined rule, wrong shapes and unknown outcomes are errors (fail closed).
        for bad in [
            "{}",
            r#"{"result": "allow"}"#,
            r#"{"result": {"outcome": "MAYBE"}}"#,
            r#"{"result": {"outcome": "ALLOW", "extra": 1}}"#,
            "not json",
        ] {
            assert!(parse_response(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
